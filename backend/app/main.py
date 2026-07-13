# backend/app/main.py
"""
OgunAI FastAPI Entry Point

Lean version of v3's main.py:
- No Celery/Redis (BackgroundTasks does the job)
- No WebSocket (poll GET /sessions/{uuid})
- No MCP server
- Same: CORS, exception handlers, router mounting, scheduler

One process. One server. Everything runs here.
"""
# main.py — add before router imports
from dotenv import load_dotenv
load_dotenv() 
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]  # goes up: app → backend → OgunAI-Scout
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from .database import engine
from .config import settings
from .database import create_tables
from .core.exceptions import OgunAIException
from .routers import auth, sessions, clients, findings, reports, dashboard, defenses

from .services.scheduler import scheduler
# ── Lifespan ──────────────────────────────────────────────────────────────────

# backend/app/main.py (Replace the lifespan function)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[OgunAI] Starting up — {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"[OgunAI] Environment: {settings.ENVIRONMENT}")
    print(f"[OgunAI] Database: {settings.DATABASE_URL.split('://')[0]}")

    create_tables()

    # FIX ORPHANED SESSIONS (Crash recovery)
    from .database import SessionLocal
    from .models import AuditSession, SessionStatus
    from datetime import datetime, UTC
    db = SessionLocal()
    try:
        orphaned = db.query(AuditSession).filter(AuditSession.status == SessionStatus.RUNNING).all()
        for s in orphaned:
            print(f"[STARTUP] Found orphaned session {s.session_uuid}. Marking as FAILED.")
            s.status = SessionStatus.FAILED
            s.error_message = "Server restarted during execution."
            s.completed_at = datetime.now(UTC)
        db.commit()
    finally:
        db.close()

    scheduler.start()
    yield
    scheduler.stop()
    engine.dispose()
    print("[OgunAI] Shutting down")

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="OgunAI — Passive Security Audit",
    description="Automated weekly passive security audit for Nigerian fintechs",
    version=settings.APP_VERSION,
    # Hide docs in production — Swagger UI is for dev only
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url=None,
    lifespan=lifespan
)


# ── Exception Handlers ────────────────────────────────────────────────────────

@app.exception_handler(OgunAIException)
async def ogunai_exception_handler(request: Request, exc: OgunAIException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.error_code, "message": exc.message, "details": exc.details}}
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = [
        {"field": " -> ".join(str(x) for x in e["loc"]), "message": e["msg"]}
        for e in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": {"code": "VALIDATION_ERROR", "message": "Invalid input", "details": errors}}
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Catch-all: log full error internally, show only generic message externally.
    This is exactly what OgunAI's check_information_disclosure tool looks for
    in other people's apps — don't be the bad example.
    """
    import logging
    logging.getLogger("ogunai").exception(f"Unhandled error: {exc}")

    if settings.DEBUG:
        import traceback
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "detail": traceback.format_exc()}}
        )
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_ERROR", "message": "An internal error occurred"}}
    )


# ── Middleware ─────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"]
)


@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    response.headers["X-Response-Time"] = f"{(time.time() - start) * 1000:.1f}ms"
    return response


# ── Routers ───────────────────────────────────────────────────────────────────

PREFIX = "/api/v1"
app.include_router(auth.router,       prefix=PREFIX, tags=["Auth"])
app.include_router(sessions.router,   prefix=PREFIX, tags=["Sessions"])
app.include_router(clients.router,    prefix=PREFIX, tags=["Clients"])
app.include_router(findings.router,   prefix=PREFIX, tags=["Findings"])
app.include_router(reports.router,    prefix=PREFIX, tags=["Reports"])
app.include_router(dashboard.router,  prefix=PREFIX, tags=["Dashboard"])
app.include_router(defenses.router,   prefix=PREFIX, tags=["Defenses"])


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health():
    """Minimal health check for uptime monitoring."""
    return {"status": "ok", "version": settings.APP_VERSION}


@app.get("/", tags=["Root"])
def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.ENVIRONMENT == "development" else None
    }