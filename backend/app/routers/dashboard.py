# backend/app/routers/dashboard.py
"""
Dashboard Router

Provides aggregated metrics for the security dashboard.
This is what the CTO or security lead sees first — the big picture.

Endpoint:
GET /api/v1/dashboard/summary → Aggregated stats across all clients
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, UTC, timedelta

from ..database import get_db
from ..models import Client, AuditSession as SessionModel, Finding, SessionStatus, Severity
from ..schemas import DashboardSummary
from ..dependencies import get_current_user

router = APIRouter(prefix="/dashboard")


@router.get("/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Executive dashboard — the first thing leadership sees.
    
    Aggregates across all clients and sessions to give a
    high-level view of the organisation's security posture.
    """
    now = datetime.now(UTC)
    one_week_ago = now - timedelta(days=7)
    one_month_ago = now - timedelta(days=30)
    
    # ── Client metrics ───────────────────────────────────────────────
    total_clients = db.query(Client).count()
    active_clients = db.query(Client).filter(Client.is_active == True).count()
    
    # ── Session metrics ──────────────────────────────────────────────
    total_sessions = db.query(SessionModel).count()
    sessions_this_week = db.query(SessionModel).filter(
        SessionModel.created_at >= one_week_ago
    ).count()
    sessions_this_month = db.query(SessionModel).filter(
        SessionModel.created_at >= one_month_ago
    ).count()
    
    # ── Finding metrics ──────────────────────────────────────────────
    total_findings = db.query(Finding).count()
    open_findings = db.query(Finding).filter(Finding.status == "open").count()
    
    critical_findings = db.query(Finding).filter(
        Finding.severity == Severity.CRITICAL,
        Finding.status == "open"
    ).count()
    
    high_findings = db.query(Finding).filter(
        Finding.severity == Severity.HIGH,
        Finding.status == "open"
    ).count()
    
    # ── Findings by severity breakdown ───────────────────────────────
    findings_by_severity = {}
    for sev in Severity:
        count = db.query(Finding).filter(Finding.severity == sev).count()
        findings_by_severity[sev.value] = count
    
    # ── Findings by attack family (top 10) ───────────────────────────
    family_counts = db.query(
        Finding.attack_family,
        func.count(Finding.id).label("count")
    ).group_by(Finding.attack_family).order_by(desc("count")).limit(10).all()
    
    findings_by_family = {row.attack_family: row.count for row in family_counts}
    
    # ── Sessions over time (last 30 days, daily) ─────────────────────
    sessions_over_time = []
    for days_ago in range(30, -1, -1):
        day = now - timedelta(days=days_ago)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        session_count = db.query(SessionModel).filter(
            SessionModel.created_at >= day_start,
            SessionModel.created_at < day_end
        ).count()
        
        finding_count = db.query(Finding).filter(
            Finding.created_at >= day_start,
            Finding.created_at < day_end
        ).count()
        
        sessions_over_time.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "sessions": session_count,
            "findings": finding_count
        })
    
    # ── Top vulnerable clients ────────────────────────────────────────
    client_findings = db.query(
        Client.id,
        Client.name,
        func.count(Finding.id).label("finding_count"),
        func.sum(
            # Weight by severity for risk score
            func.case(
                (Finding.severity == Severity.CRITICAL, 25),
                (Finding.severity == Severity.HIGH, 10),
                (Finding.severity == Severity.MEDIUM, 3),
                else_=1
            )
        ).label("risk_score")
    ).join(Finding, Finding.client_id == Client.id, isouter=True).filter(
        Finding.status == "open"
    ).group_by(Client.id, Client.name).order_by(desc("risk_score")).limit(5).all()
    
    top_vulnerable = [
        {
            "client_id": row.id,
            "client_name": row.name,
            "open_findings": row.finding_count or 0,
            "risk_score": min(100, row.risk_score or 0)
        }
        for row in client_findings
    ]
    
    # ── Overall risk score ────────────────────────────────────────────
    overall_risk = min(100, (
        critical_findings * 25 +
        high_findings * 10
    ))
    
    return {
        "total_clients": total_clients,
        "active_clients": active_clients,
        "total_sessions": total_sessions,
        "sessions_this_week": sessions_this_week,
        "sessions_this_month": sessions_this_month,
        "total_findings": total_findings,
        "open_findings": open_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "findings_by_severity": findings_by_severity,
        "findings_by_family": findings_by_family,
        "sessions_over_time": sessions_over_time,
        "top_vulnerable_clients": top_vulnerable,
        "overall_risk_score": float(overall_risk)
    }