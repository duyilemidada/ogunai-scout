# backend/app/routers/findings.py
"""
Findings Router

Endpoints:
GET    /api/v1/findings                    → All findings (filterable)
GET    /api/v1/sessions/{uuid}/findings    → Findings for a specific session
GET    /api/v1/findings/{id}               → Single finding detail
PATCH  /api/v1/findings/{id}              → Update status (mark remediated)
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional
from datetime import datetime, UTC
from ..database import get_db
from ..models import Finding, AuditSession  as SessionModel, Severity
from ..schemas import FindingResponse, FindingList, FindingUpdate
from ..dependencies import get_current_user, require_role
from ..core.exceptions import NotFoundError

router = APIRouter(prefix="/findings")


@router.get("", response_model=FindingList)
def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW"),
    client_id: Optional[int] = Query(None),
    attack_family: Optional[str] = Query(None),
    status: Optional[str] = Query(None, description="Filter: open, remediated, false_positive"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    List all findings across all sessions with filtering.
    
    The primary endpoint for a developer who wants to see
    "what do I need to fix?" across all clients.
    """
    query = db.query(Finding)
    
    if severity:
        try:
            sev_enum = Severity(severity.upper())
            query = query.filter(Finding.severity == sev_enum)
        except ValueError:
            pass
    
    if client_id:
        query = query.filter(Finding.client_id == client_id)
    
    if attack_family:
        query = query.filter(Finding.attack_family.ilike(f"%{attack_family}%"))
    
    if status:
        query = query.filter(Finding.status == status)
    
    total = query.count()
    findings = query.order_by(desc(Finding.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()
    
    # Severity breakdown for the response
    all_findings = db.query(Finding)
    if client_id:
        all_findings = all_findings.filter(Finding.client_id == client_id)
    
    severity_breakdown = {}
    for sev in Severity:
        count = all_findings.filter(Finding.severity == sev.value).count()
        if count > 0:
            severity_breakdown[sev.value] = count
    
    return {
        "items": findings,
        "total": total,
        "page": page,
        "page_size": page_size,
        "severity_breakdown": severity_breakdown
    }


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get full detail for a single finding including evidence and compliance refs."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise NotFoundError("Finding", details={"id": finding_id})
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding_status(
    finding_id: int,
    data: FindingUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("analyst"))
):
    """
    Update finding status for remediation tracking.
    
    When a developer fixes something, they mark it 'remediated' here.
    This feeds into the trend analysis in the dashboard —
    showing which clients are actively fixing issues.
    """
    from datetime import datetime, UTC
    
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise NotFoundError("Finding", details={"id": finding_id})
    
    finding.status = data.status
    
    if data.status == "remediated":
        finding.remediated_at = datetime.now(UTC)
    
    db.commit()
    db.refresh(finding)
    return finding