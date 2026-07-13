# backend/app/services/scheduler.py
"""
Weekly Audit Scheduler using APScheduler

This replaces Celery for the scheduled-run use case.
APScheduler runs inside the FastAPI process — no Redis, no separate worker,
no virtualization required.

For your hardware (8GB RAM, no virtualization), this is the right choice.
For production scale (50+ clients), you would move to Celery + Redis.

How it works:
- Scheduler starts when FastAPI starts (lifespan event)
- Every Monday at 6am, it queries active clients and triggers sessions
- Individual session runs use FastAPI BackgroundTasks (also in-process)

Limitation: if the server restarts mid-session, that session is lost.
For your use case (your own apps + handful of clients), acceptable.
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, UTC
from uuid import uuid4
from typing import Optional
import yaml
import logging

logger = logging.getLogger("ogunai.scheduler")


class AuditScheduler:
    """
    Manages weekly automated audit runs.
    
    Wraps APScheduler with domain-specific logic:
    - Loads all active clients from database
    - Triggers audit sessions for each
    - Updates session status in database
    - Handles failures without crashing the scheduler
    """
    
    def __init__(self):
        # AsyncIOScheduler works inside an async FastAPI app
        # It uses the same event loop as FastAPI
        self.scheduler = BackgroundScheduler(timezone="Africa/Lagos")
        self._is_running = False
    
    def start(self):
        """Start the scheduler. Called in FastAPI lifespan startup."""
        if self._is_running:
            return
        
        # Weekly audit: every Monday at 6am Lagos time
        self.scheduler.add_job(
            self._run_weekly_audits,
            trigger=CronTrigger(
                day_of_week="mon",
                hour=6,
                minute=0
            ),
            id="weekly_audit",
            name="Weekly Security Audit",
            replace_existing=True,
            misfire_grace_time=3600  # Run up to 1 hour late if server was down
        )
        
        self.scheduler.start()
        self._is_running = True
        logger.info("Audit scheduler started — weekly runs every Monday 06:00 WAT")
    
    def stop(self):
        """Stop the scheduler. Called in FastAPI lifespan shutdown."""
        if self._is_running:
            self.scheduler.shutdown(wait=False)
            self._is_running = False
            logger.info("Audit scheduler stopped")
    
    async def _run_weekly_audits(self):
        """
        Main scheduled job — runs all active clients.
        
        Called automatically every Monday. Can also be triggered manually
        via the /api/v1/scheduler/trigger endpoint for testing.
        """
        from ..database import SessionLocal
        from ..models import Client, AuditSession as SessionModel, SessionStatus
        
        logger.info(f"Weekly audit started at {datetime.now(UTC).isoformat()}")
        
        db = SessionLocal()
        try:
            # Load all active clients
            clients = db.query(Client).filter(Client.is_active == True).all()
            logger.info(f"Running audits for {len(clients)} active clients")
            
            for client in clients:
                try:
                    await self._audit_single_client(client, db)
                except Exception as e:
                    # One client failing should not stop the rest
                    logger.exception(f"Audit failed for client {client.name}: {e}")
        
        finally:
            db.close()
        
        logger.info("Weekly audit batch complete")
    
    async def _audit_single_client(self, client, db):
        """Run a complete audit for one client."""
        from ..models import AuditSession as SessionModel, SessionStatus
        import asyncio
        
        # Create session record
        session_uuid = str(uuid4())
        session = SessionModel(
            client_id=client.id,
            session_uuid=session_uuid,
            name=f"Weekly Audit — {datetime.now(UTC).strftime('%Y-%m-%d')}",
            status=SessionStatus.RUNNING,
            max_iterations=20
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        
        logger.info(f"Starting audit for {client.name} (session {session_uuid})")
        
        # Run the engine in a thread to avoid blocking the event loop
        # The OgunAI agent makes many synchronous HTTP requests and LLM calls
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,  # Default thread pool
            self._run_engine_sync,
            client.profile_yaml,
            client.auth_config.get("api_key") if client.auth_type == "api_key" else None,
            session.id,
            client.id
        )
        
        # Update session with results
        from datetime import datetime, UTC
        session.status = SessionStatus.COMPLETED
        session.completed_at = datetime.now(UTC)
        session.findings_count = result.get("findings_count", 0)
        session.report_markdown_path = result.get("report_path")
        db.commit()
        
        logger.info(
            f"Audit complete for {client.name}: "
            f"{result.get('findings_count', 0)} findings"
        )
    
    def _run_engine_sync(
        self,
        profile_yaml: str,
        api_key: Optional[str],
        session_id: int,
        client_id: int
    ) -> dict:
        """
        Synchronous engine execution (runs in thread pool).
        
        This is the actual OgunAI engine run — separated into sync
        because the engine uses synchronous requests/LLM calls.
        """
        import yaml as yaml_lib
        import sys
        from pathlib import Path

        # Import engine
        ENGINE_ROOT = Path(__file__).resolve().parents[3] / "engine"
        if str(ENGINE_ROOT) not in sys.path:
           sys.path.insert(0, str(ENGINE_ROOT))
        from engine.ogunai.agent import OgunAIAgent
        from engine.ogunai.llm_adapter import get_default_adapter
        from engine.ogunai.report import generate_markdown_report, save_report
        
        # Import passive tools and register them
        from engine.ogunai.tools_passive import (
            check_security_headers, scan_sensitive_paths,
            check_ssl_tls, check_dns_email_security,
            check_cors_policy, check_rate_limiting,
            check_information_disclosure, scan_dependencies,
            write_finding
        )
        from engine.ogunai.agent import register_tool
        
        # Register all passive tools
        register_tool("check_security_headers", check_security_headers)
        register_tool("scan_sensitive_paths", scan_sensitive_paths)
        register_tool("check_ssl_tls", check_ssl_tls)
        register_tool("check_dns_email_security", check_dns_email_security)
        register_tool("check_cors_policy", check_cors_policy)
        register_tool("check_rate_limiting", check_rate_limiting)
        register_tool("check_information_disclosure", check_information_disclosure)
        register_tool("scan_dependencies", scan_dependencies)
        register_tool("write_finding", write_finding)
        
        # Parse profile
        profile = yaml_lib.safe_load(profile_yaml)
        profile["_api_key"] = api_key
        
        # Run
        llm = get_default_adapter()
        agent = OgunAIAgent(profile=profile, llm=llm)
        result = agent.run()
        
        # Save findings to database
        self._save_findings_to_db(result["findings"], [])
        
        return result
    
    def _save_findings_to_db(self, findings: list, session_id: int, client_id: int):
        """Save engine findings to the database."""
        from ..database import SessionLocal
        from ..models import Finding, Severity
        
        db = SessionLocal()
        try:
            for finding_data in findings:
                severity_str = finding_data.get("severity", "LOW")
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.LOW
                
                finding = Finding(
                    session_id=session_id,
                    client_id=client_id,
                    attack_family=finding_data.get("attack_family", "UNKNOWN"),
                    severity=severity.value,
                    title=finding_data.get("title", "Untitled"),
                    description=finding_data.get("description", ""),
                    evidence={
                        **finding_data.get("evidence", {}),
                        "compliance_references": finding_data.get("compliance_references", [])
                    },
                    recommendation=finding_data.get("recommendation", ""),
                    endpoint=finding_data.get("endpoint")
                )
                db.add(finding)
            
            db.commit()
        finally:
            db.close()


# Singleton — imported by main.py lifespan
scheduler = AuditScheduler()