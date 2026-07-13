# backend/app/database.py
"""
Database Connection Management

SQLite for local use, no server required.
SQLAlchemy handles the connection pooling and session lifecycle.

One change (DATABASE_URL env var) moves this to PostgreSQL.
Everything else stays the same.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from .config import settings
from .models import Base
from typing import Generator

def _build_engine():
    """
    Create a SQLAlchemy engine with settings appropriate for the DB type.

    SQLite needs special handling:
    - check_same_thread=False: SQLite defaults to single-thread. FastAPI is
      async and uses multiple threads. We disable this check because SQLAlchemy
      already handles thread safety via its session management.
    - PRAGMA foreign_keys=ON: SQLite doesn't enforce foreign keys by default.
      We turn this on so cascaded deletes (Client → Sessions → Findings) work.

    PostgreSQL gets connection pooling settings instead.
    """
    if settings.DATABASE_URL.startswith("sqlite"):
        engine = create_engine(
            settings.DATABASE_URL,
            connect_args={"check_same_thread": False},
            echo=settings.DEBUG  # When DEBUG=True, log every SQL query
        )

        # Enable foreign key enforcement for every SQLite connection
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine
    else:
        # PostgreSQL / other relational DBs
        return create_engine(
            settings.DATABASE_URL,
            pool_size=5,           # 5 connections held open permanently
            max_overflow=10,       # Up to 10 extra connections when busy
            pool_timeout=30,       # Wait 30s for a connection before erroring
            echo=settings.DEBUG
        )


engine = _build_engine()

# Session factory — never use this directly outside FastAPI dependencies.
# Use get_db() via Depends() instead, which closes the session automatically.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_tables():
    """
    Create all tables. Called once at startup.

    In production with real migrations, comment this out and use:
        alembic upgrade head
    For our use case (SQLite, one person, rarely changing schema),
    create_all is fine — it's a no-op if tables already exist.
    """
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides one database session per request.

    Usage in a router:
        @router.get("/clients")
        def list_clients(db: Session = Depends(get_db)):
            return db.query(Client).all()

    The try/finally ensures the session always closes even if an exception
    is raised inside the route handler — no connection leaks.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()