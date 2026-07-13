# backend/app/schemas.py
"""
Pydantic Schemas — Request/Response Contracts

Every API endpoint uses these for:
1. Request body validation (automatic 422 if invalid)
2. Response serialization (automatic JSON conversion)
3. OpenAPI documentation (Swagger UI reads these)

Lean version removes:
- SARIF report format
- Complex orchestration schemas
- MCP server schemas
"""

from pydantic import BaseModel, Field, HttpUrl, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime


# ── Auth ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: str = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, description="Min 8 characters")
    full_name: Optional[str] = None
    role: str = Field(default="analyst", pattern="^(admin|analyst|viewer)$")


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ── API Keys ──────────────────────────────────────────────────────────────────

class ApiKeyCreate(BaseModel):
    name: Optional[str] = Field(None, description="Human-readable label for this key")


class ApiKeyResponse(BaseModel):
    """
    Returned ONCE when a key is created. The raw key is never stored.
    If lost, the user must delete this key and create a new one.
    """
    id: int
    key_prefix: str
    name: Optional[str]
    raw_key: Optional[str] = Field(
        None,
        description="Only present on creation. Store this — you won't see it again."
    )
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Clients ───────────────────────────────────────────────────────────────────

class ClientCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    target_url: HttpUrl
    target_type: str = Field(
        default="full_spectrum",
        pattern="^(ml_only|traditional_only|full_spectrum)$"
    )
    profile_yaml: str = Field(..., min_length=10)
    auth_type: Optional[str] = Field(
        default="none",
        pattern="^(none|api_key|bearer_token|basic)$"
    )
    auth_config: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ClientResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    target_url: str
    target_type: str
    is_active: bool
    created_at: datetime
    session_count: int = 0
    last_session_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ClientList(BaseModel):
    items: List[ClientResponse]
    total: int
    page: int
    page_size: int


# ── Sessions ──────────────────────────────────────────────────────────────────

class SessionCreate(BaseModel):
    client_id: int
    name: Optional[str] = None
    # Optional: provide the client's API key at session-trigger time.
    # This is injected at runtime and never stored in the database.
    client_api_key: Optional[str] = Field(
        None,
        description="API key for the target system. Not stored — used only during this session."
    )


class SessionStatusResponse(BaseModel):
    session_uuid: str
    status: str
    client_name: str
    findings_count: int = 0
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: float = 0.0
    report_available: bool = False
    error_message: Optional[str] = None

    model_config = {"from_attributes": True}


class SessionList(BaseModel):
    items: List[SessionStatusResponse]
    total: int
    page: int
    page_size: int


# ── Findings ──────────────────────────────────────────────────────────────────

class FindingResponse(BaseModel):
    id: int
    attack_family: str
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any]
    recommendation: str
    endpoint: Optional[str]
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingList(BaseModel):
    items: List[FindingResponse]
    total: int
    page: int
    page_size: int
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)


class FindingUpdate(BaseModel):
    status: str = Field(
        ...,
        pattern="^(open|confirmed|false_positive|remediated)$"
    )


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardSummary(BaseModel):
    total_clients: int
    active_clients: int
    total_sessions: int
    sessions_this_week: int
    total_findings: int
    open_findings: int
    critical_findings: int
    high_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_family: Dict[str, int]
    sessions_over_time: List[Dict[str, Any]]
    top_vulnerable_clients: List[Dict[str, Any]]
    overall_risk_score: float