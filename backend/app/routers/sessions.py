# backend/app/routers/sessions.py
"""
Session Management Router

Key difference from v3: BackgroundTasks instead of Celery.

In v3, triggering a session enqueued a Celery task via Redis.
Here, we call FastAPI's built-in BackgroundTasks — the task runs in the
same process, in a thread pool executor, while the API continues responding.

Limitation: if the server restarts, the background task dies.
For one server, a handful of clients, weekly audits — this is acceptable.
If you ever need reliability across restarts, switch back to Celery.
But that's a later problem.

Endpoints:
POST /api/v1/sessions           → Trigger a new audit session
GET  /api/v1/sessions           → List sessions (paginated)
GET  /api/v1/sessions/{uuid}    → Get status + results
POST /api/v1/sessions/{uuid}/cancel → Cancel if still running
"""

import asyncio
from uuid import uuid4
from datetime import datetime, UTC
from typing import Optional

from fastapi import APIRouter, Depends, BackgroundTasks, Query, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc

from ..database import get_db
from ..models import AuditSession, SessionStatus, Client, Finding, Severity, User
from ..schemas import SessionCreate, SessionStatusResponse, SessionList, FindingList
from ..dependencies import get_current_user, require_role
from ..core.exceptions import NotFoundError, ValidationError, ConflictError
from ..config import settings
from pathlib import Path
from sqlalchemy import case
router = APIRouter(prefix="/sessions")


# ── The actual background task ─────────────────────────────────────────────────

def _run_audit_in_background(
    session_id: int,
    profile_yaml: str,
    client_api_key: Optional[str]
):
    import sys
    import traceback
    import yaml
    import json                          # ← added for safe evidence parsing
    from pathlib import Path
    from datetime import datetime, UTC

    # ── Step 1: Get DB connection FIRST so we can record any failure ──────────
    from ..database import SessionLocal
    db = SessionLocal()

    def mark_failed(error_msg: str):
        try:
            s = db.query(AuditSession).filter(AuditSession.id == session_id).first()
            if s:
                s.status = SessionStatus.FAILED
                s.completed_at = datetime.now(UTC)
                s.error_message = error_msg[:1000]
                db.commit()
                print(f"[AUDIT] Session {session_id} marked FAILED: {error_msg[:200]}")
        except Exception as db_err:
            print(f"[AUDIT] Could not mark session failed: {db_err}")

    try:
        # ── Step 2: Mark as running ───────────────────────────────────────────
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            print(f"[AUDIT] Session {session_id} not found in DB")
            return

        session.status = SessionStatus.RUNNING
        session.started_at = datetime.now(UTC)
        db.commit()
        print(f"[AUDIT] Session {session_id} marked RUNNING")

        # ── Step 3: Add project root to path ─────────────────────────────────
        PROJECT_ROOT = Path(__file__).resolve().parents[3]  # OgunAI-Scout/
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.insert(0, str(PROJECT_ROOT))
        print(f"[AUDIT] Project root: {PROJECT_ROOT}")

        # ── Step 4: Import engine — any ImportError is caught and recorded ────
        try:
            from engine.ogunai.agent import OgunAIAgent, register_tool
            from engine.ogunai.llm_adapter import get_default_adapter
            from engine.ogunai.memory import load_memory, record_session, save_memory
            from engine.ogunai.report import generate_markdown_report, save_report
            from engine.ogunai.tools_passive import (
                check_security_headers, scan_sensitive_paths, check_ssl_tls,
                check_dns_email_security, check_cors_policy, check_rate_limiting,
                check_information_disclosure, scan_dependencies, write_finding,
                audit_orm_safety,
            )
            print("[AUDIT] Engine imports OK")
        except ImportError as e:
            mark_failed(f"Engine import failed: {e}\n\nInstall missing packages in backend venv:\npip install openai dnspython pyyaml")
            return

        # ── Step 5: Register tools ────────────────────────────────────────────
        register_tool("check_security_headers", check_security_headers)
        register_tool("scan_sensitive_paths", scan_sensitive_paths)
        register_tool("check_ssl_tls", check_ssl_tls)
        register_tool("check_dns_email_security", check_dns_email_security)
        register_tool("check_cors_policy", check_cors_policy)
        register_tool("check_rate_limiting", check_rate_limiting)
        register_tool("check_information_disclosure", check_information_disclosure)
        register_tool("scan_dependencies", scan_dependencies)
        register_tool("write_finding", write_finding)
        register_tool("audit_orm_safety", audit_orm_safety)
        print("[AUDIT] Tools registered")

        # ── Step 6: Run the agent ─────────────────────────────────────────────
        profile = yaml.safe_load(profile_yaml)
        profile["_api_key"] = client_api_key

        llm = get_default_adapter()
        agent = OgunAIAgent(profile=profile, llm=llm)
        print("[AUDIT] Agent created, starting run...")
        result = agent.run()
        print(f"[AUDIT] Agent finished. Findings: {len(result.get('findings', []))}")

        # ── Step 7: Save findings ─────────────────────────────────────────────
        for finding_data in result.get("findings", []):
            try:
                severity = Severity(finding_data.get("severity", "LOW"))
            except ValueError:
                severity = Severity.LOW

            # ── FIX: Ensure evidence is always a dict before merging ──────────
            evidence = finding_data.get("evidence", {})
            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except (json.JSONDecodeError, TypeError):
                    evidence = {"raw": evidence}
            if not isinstance(evidence, dict):
                evidence = {"value": str(evidence)}

            compliance_refs = finding_data.get("compliance_references", [])
            if not isinstance(compliance_refs, list):
                compliance_refs = [compliance_refs] if compliance_refs else []

            finding = Finding(
                session_id=session.id,
                client_id=session.client_id,
                attack_family=finding_data.get("attack_family", "UNKNOWN"),
                severity=severity.value,
                title=finding_data.get("title", "Untitled"),
                description=finding_data.get("description", ""),
                evidence={
                    **evidence,
                    "compliance_references": compliance_refs
                },
                recommendation=finding_data.get("recommendation", ""),
                endpoint=finding_data.get("endpoint")
            )
            db.add(finding)

        # ── Step 8: Generate report ───────────────────────────────────────────
        report_path = None
        if result.get("findings"):
            report_text = generate_markdown_report(
                findings=result["findings"],
                target_url=profile.get("api_url", ""),
                client_name=profile.get("client_name", "Unknown"),
                session_metadata={"duration_seconds": result.get("duration_seconds", 0)}
            )
            report_path = save_report(report_text, profile.get("client_name"))

        # ── Step 9: Update memory ─────────────────────────────────────────────
        memory = load_memory()
        record_session(memory, profile.get("client_name", "unknown"), result.get("findings", []))
        save_memory(memory)

        # ── Step 10: Mark completed ───────────────────────────────────────────
        session.status = SessionStatus.COMPLETED
        session.completed_at = datetime.now(UTC)
        session.findings_count = len(result.get("findings", []))
        session.report_markdown_path = report_path
        db.commit()
        print(f"[AUDIT] Session {session_id} COMPLETED. {session.findings_count} findings.")

    except Exception as e:
        mark_failed(f"{type(e).__name__}: {str(e)}\n\n{traceback.format_exc()}")

    finally:
        db.close()
# ── Router endpoints ───────────────────────────────────────────────────────────

@router.post("", response_model=SessionStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_session(
    data: SessionCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Trigger a new audit session.

    Returns 202 ACCEPTED immediately. The audit runs as a background task.
    Poll GET /sessions/{uuid} for status updates.

    To check when it's done: poll until status is "completed" or "failed".
    Reports are available at GET /sessions/{uuid}/report when completed.
    """
    client = db.query(Client).filter(Client.id == data.client_id).first()
    if not client:
        raise NotFoundError("Client", details={"id": data.client_id})

    if not client.is_active:
        raise ValidationError("Client is deactivated")

    # Create session record
    session_uuid = str(uuid4())
    session = AuditSession(
        client_id=client.id,
        session_uuid=session_uuid,
        name=data.name or f"Audit {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')}",
        status=SessionStatus.PENDING,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    # Queue in background — this returns immediately
    # The task runs in the thread pool while the API keeps serving other requests
    background_tasks.add_task(
        _run_audit_in_background,
        session_id=session.id,
        profile_yaml=client.profile_yaml,
        client_api_key = data.client_api_key or (client.auth_config or {}).get("api_key")
    )

    return SessionStatusResponse(
        session_uuid=session_uuid,
        status=SessionStatus.PENDING,
        client_name=client.name,
        findings_count=0,
        started_at=None,
        completed_at=None
    )


@router.get("", response_model=SessionList)
def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    client_id: Optional[int] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List audit sessions with pagination and optional filtering."""
    query = db.query(AuditSession).options(joinedload(AuditSession.client))

    if client_id:
        query = query.filter(AuditSession.client_id == client_id)
    if status_filter:
        query = query.filter(AuditSession.status == status_filter)

    total = query.count()
    sessions = query.order_by(desc(AuditSession.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    items = []
    for s in sessions:
        items.append(SessionStatusResponse(
            session_uuid=s.session_uuid,
            status=s.status,
            client_name=s.client.name if s.client else "Unknown",
            findings_count=s.findings_count or 0,
            started_at=s.started_at,
            completed_at=s.completed_at,
            duration_seconds=s.duration_seconds(),
            report_available=bool(s.report_markdown_path),
            error_message=s.error_message
        ))

    return SessionList(items=items, total=total, page=page, page_size=page_size)


@router.get("/{session_uuid}", response_model=SessionStatusResponse)
def get_session(
    session_uuid: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get session status and results.

    Poll this endpoint to check if an audit is complete.
    When status == "completed", the report is ready.
    """
    session = db.query(AuditSession).filter(
        AuditSession.session_uuid == session_uuid
    ).first()

    if not session:
        raise NotFoundError("Session", details={"uuid": session_uuid})

    return SessionStatusResponse(
        session_uuid=session.session_uuid,
        status=session.status,
        client_name=session.client.name if session.client else "Unknown",
        findings_count=session.findings_count or 0,
        started_at=session.started_at,
        completed_at=session.completed_at,
        duration_seconds=session.duration_seconds(),
        report_available=bool(session.report_markdown_path),
        error_message=session.error_message
    )


@router.get("/{session_uuid}/findings", response_model=FindingList)
def get_session_findings(
    session_uuid: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all findings for a specific session."""
    session = db.query(AuditSession).filter(
        AuditSession.session_uuid == session_uuid
    ).first()

    if not session:
        raise NotFoundError("Session", details={"uuid": session_uuid})
    
    severity_order = case(
        (Finding.severity == "CRITICAL", 1),
        (Finding.severity == "HIGH", 2),
        (Finding.severity == "MEDIUM", 3),
        (Finding.severity == "LOW", 4),
        (Finding.severity == "PASS", 5),
        else_=6
    )

    findings = db.query(Finding).filter(
        Finding.session_id == session.id
    ).order_by(severity_order).all()

    severity_breakdown = {}
    for f in findings:
        severity_breakdown[f.severity] = severity_breakdown.get(f.severity, 0) + 1

    return FindingList(
        items=findings,
        total=len(findings),
        page=1,
        page_size=len(findings),
        severity_breakdown=severity_breakdown
    )