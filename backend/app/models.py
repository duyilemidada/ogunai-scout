# backend/app/models.py
"""
SQLAlchemy ORM Models

These models define the database schema.
Each class maps to one table. Relationships define how they connect.

Key design decisions for the lean version:
- Removed SessionEvent (we don't need real-time streaming infrastructure)
- ApiKey has a key_prefix column for fast indexed lookup (fixes the O(n) bug)
- SessionStatus is simplified (no PAUSED, no QUEUED — just the states we use)
"""

from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean,
    ForeignKey, JSON, Float
)
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime, UTC
import enum

Base = declarative_base()


class SessionStatus(str, enum.Enum):
    """
    The four states an audit session can be in.
    PENDING → RUNNING → COMPLETED or FAILED

    We removed QUEUED and PAUSED from v3 because:
    - QUEUED only makes sense with a real queue (Celery). We use BackgroundTasks.
    - PAUSED (human-in-the-loop) is a future feature, not now.
    """
    PENDING = "pending"      # Created, not yet started
    RUNNING = "running"      # BackgroundTask is executing
    COMPLETED = "completed"  # Finished, report ready
    FAILED = "failed"        # Error occurred


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    PASS = "PASS"


class Client(Base):
    """
    A client is a system being audited.
    One client → many sessions → many findings.

    profile_yaml stores the complete YAML profile as text.
    The actual API key is NEVER stored here — it's injected at runtime
    from environment or provided by the user when triggering a session.
    """
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    profile_yaml = Column(Text, nullable=False)   # Full YAML profile text
    target_url = Column(String(512), nullable=False)
    target_type = Column(String(50), default="full_spectrum")
    auth_type = Column(String(50), default="none")  # none | api_key | bearer_token
    auth_config = Column(JSON, default=dict)        # {header_name: "X-API-KEY"} etc
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime, default=lambda: datetime.now(UTC),
                        onupdate=lambda: datetime.now(UTC))

    sessions = relationship("AuditSession", back_populates="client",
                            cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="client",
                            cascade="all, delete-orphan")


class AuditSession(Base):
    """
    One audit run against a client.

    We name this AuditSession not Session to avoid confusion
    with SQLAlchemy's own Session class.
    """
    __tablename__ = "audit_sessions"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    client = relationship("Client", back_populates="sessions")

    session_uuid = Column(String(36), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True)
    status = Column(String(20), default=SessionStatus.PENDING, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    max_iterations = Column(Integer, default=20)
    # Results
    findings_count = Column(Integer, default=0)
    report_markdown_path = Column(String(512), nullable=True)
    error_message = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="session",
                            cascade="all, delete-orphan")

    def duration_seconds(self) -> float:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0


class Finding(Base):
    """
    A confirmed security issue discovered during an audit session.
    This is the core deliverable — what clients pay for.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("audit_sessions.id"), nullable=False)
    session = relationship("AuditSession", back_populates="findings")
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    client = relationship("Client", back_populates="findings")

    attack_family = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # Severity enum value
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, default=dict)
    recommendation = Column(Text, nullable=False)
    endpoint = Column(String(512), nullable=True)

    # Remediation tracking
    status = Column(String(50), default="open")  # open | confirmed | false_positive | remediated
    remediated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


class User(Base):
    """
    Dashboard users — the humans who use OgunAI.
    Separate from client API keys (those are for machines, not people).
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="analyst")  # admin | analyst | viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    last_login = Column(DateTime, nullable=True)

    api_keys = relationship("ApiKey", back_populates="user",
                            cascade="all, delete-orphan")


class ApiKey(Base):
    """
    API keys for programmatic access.

    The O(n) bcrypt bug fix:
    In v3, authentication iterated through ALL keys doing bcrypt.verify() on each.
    bcrypt is intentionally slow (100ms+), so with 10 keys that's 1000ms per request.

    Fix: store a fast-lookup prefix.
    - Key format: ogunai_{8_char_prefix}_{random_part}
    - key_prefix is indexed in the DB
    - Authentication: extract prefix from key → 1 DB query → 1 bcrypt verify
    - Result: O(1) lookup + 1 bcrypt verify, regardless of how many keys exist
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="api_keys")

    # INDEXED for fast lookup (this is what fixes the O(n) bug)
    key_prefix = Column(String(8), nullable=False, index=True)
    key_hash = Column(String(255), nullable=False)   # bcrypt hash of full key
    name = Column(String(255), nullable=True)

    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))