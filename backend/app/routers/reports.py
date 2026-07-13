# backend/app/routers/reports.py
"""
Reports Router

Endpoints:
GET /api/v1/sessions/{uuid}/report          → Download markdown report
GET /api/v1/sessions/{uuid}/report/pdf      → Download PDF (if generated)
GET /api/v1/clients/{id}/report/latest      → Latest report for a client
"""

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, PlainTextResponse
import os
from datetime import datetime, UTC
from ..database import get_db
from sqlalchemy.orm import Session
from ..models import AuditSession  as SessionModel, Finding, SessionStatus
from ..dependencies import get_current_user
from ..core.exceptions import NotFoundError
from ..config import settings

router = APIRouter()


@router.get("/sessions/{session_uuid}/report")
def get_session_report(
    session_uuid: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Download the markdown report for a completed session.
    
    Returns the raw markdown text. The frontend can render it,
    or the user can copy it into Notion/Confluence.
    """
    session = db.query(SessionModel).filter(
        SessionModel.session_uuid == session_uuid
    ).first()
    
    if not session:
        raise NotFoundError("Session", details={"session_uuid": session_uuid})
    
    if session.status != SessionStatus.COMPLETED.value:
        return {"message": f"Session is {session.status.value} — report not yet available."}
    
    # If we have the file path, serve the file directly
    if session.report_markdown_path and os.path.exists(session.report_markdown_path):
        return FileResponse(
            path=session.report_markdown_path,
            media_type="text/markdown",
            filename=f"ogunai_report_{session_uuid[:8]}.md"
        )
    
    # Regenerate from database findings if file is missing
    findings = db.query(Finding).filter(Finding.session_id == session.id).all()
    
    if not findings:
        return PlainTextResponse("No findings recorded for this session.")
    
    # Import the report generator from the engine
    import sys
    sys.path.insert(0, "../../engine")
    from engine.ogunai.report import generate_markdown_report
    
    findings_dicts = [
        {
            "attack_family": f.attack_family,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
            "endpoint": f.endpoint or "",
            "compliance_references": f.evidence.get("compliance_references", [])
        }
        for f in findings
    ]
    
    report_text = generate_markdown_report(
        findings=findings_dicts,
        target_url=session.client.target_url,
        client_name=session.client.name,
        session_metadata={"duration_seconds": session.duration_seconds()}
    )
    
    return PlainTextResponse(report_text, media_type="text/markdown")


@router.get("/clients/{client_id}/report/latest")
def get_latest_client_report(
    client_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get the most recent completed session report for a client."""
    from sqlalchemy import desc
    
    latest_session = db.query(SessionModel).filter(
        SessionModel.client_id == client_id,
        SessionModel.status == SessionStatus.COMPLETED
    ).order_by(desc(SessionModel.completed_at)).first()
    
    if not latest_session:
        raise NotFoundError(
            "Completed session",
            details={"client_id": client_id, "message": "No completed sessions for this client"}
        )
    
    # Redirect to the session report endpoint
    from fastapi.responses import RedirectResponse
    return RedirectResponse(f"/api/v1/sessions/{latest_session.session_uuid}/report")