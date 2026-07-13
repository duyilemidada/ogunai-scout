# backend/app/routers/defenses.py
"""
Defenses Router

Turns findings into actionable defense recommendations.
When a developer asks "how do I fix this?", this endpoint gives them
a specific code example, not generic advice.

Endpoints:
GET  /api/v1/findings/{id}/defense      → Defense recommendation for a finding
GET  /api/v1/clients/{id}/defenses      → All open defenses for a client (prioritised)
POST /api/v1/defenses/deploy            → Mark a defense as deployed (future: webhook trigger)
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import Finding, Client
from ..dependencies import get_current_user
from ..core.exceptions import NotFoundError

router = APIRouter(prefix="/defenses")


# Code-level defense recommendations per attack family
# These are the concrete fixes a developer can copy and implement
DEFENSE_PLAYBOOK = {
    "HEADER_SECURITY": {
        "title": "Add Security Headers",
        "effort": "1-2 hours",
        "priority": "HIGH",
        "fastapi_code": """
# Add to your FastAPI app startup:
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Also remove fingerprinting headers — FastAPI does not add X-Powered-By by default.
# Uvicorn adds 'Server: uvicorn' — to remove it:
# Run with: uvicorn main:app --no-access-log --header server:''
""",
        "express_code": """
// npm install helmet
const helmet = require('helmet');
app.use(helmet());

// Remove X-Powered-By
app.disable('x-powered-by');
"""
    },
    
    "SSL_TLS": {
        "title": "Fix SSL/TLS Configuration",
        "effort": "30 minutes",
        "priority": "CRITICAL",
        "fastapi_code": """
# If using Let's Encrypt with Certbot:
# certbot renew --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"
# 
# For Render (where FraudShield is deployed): Render manages certificates automatically.
# Check Render dashboard → your service → Settings → Custom Domains.
#
# Enable auto-renewal check in your deployment:
# Add to your CI/CD or cron: certbot renew --quiet
#
# To enforce TLS 1.2+ in Nginx:
# ssl_protocols TLSv1.2 TLSv1.3;
# ssl_prefer_server_ciphers on;
""",
        "general": "Let's Encrypt (https://letsencrypt.org) provides free certificates with 90-day validity. Use certbot for auto-renewal."
    },
    
    "DNS_EMAIL": {
        "title": "Configure Email Security (SPF + DMARC)",
        "effort": "2-4 hours",
        "priority": "HIGH",
        "dns_records": """
# Add these DNS TXT records via your domain registrar (e.g., Namecheap, GoDaddy, Cloudflare):

# SPF record (replace with your actual mail provider):
yourdomain.com    TXT    "v=spf1 include:sendgrid.net include:gmail.com -all"
# Common includes: include:sendgrid.net, include:mailgun.org, include:amazonses.com

# DMARC record:
_dmarc.yourdomain.com    TXT    "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; pct=100"
# p=reject: reject spoofed emails entirely (strictest, recommended)
# rua: where to send daily DMARC aggregate reports
""",
        "note": "After adding SPF and DMARC, test with https://dmarcian.com/dmarc-inspector/"
    },
    
    "CORS": {
        "title": "Fix CORS Policy",
        "effort": "1 hour",
        "priority": "HIGH",
        "fastapi_code": """
# In main.py, replace wildcard CORS with explicit origins:
from fastapi.middleware.cors import CORSMiddleware

# Get this from environment — never hardcode production URLs
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,   # Explicit list, NEVER "*" for authenticated APIs
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-KEY"],
)

# In .env:
# ALLOWED_ORIGINS=https://yourdashboard.com,https://yourapp.com
""",
        "express_code": """
const cors = require('cors');
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS.split(','),
    credentials: true
}));
"""
    },
    
    "RATE_LIMIT": {
        "title": "Implement Rate Limiting",
        "effort": "2-3 hours",
        "priority": "HIGH",
        "fastapi_code": """
# FraudShield already has SlowAPI — apply it to audit endpoints too:
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.get("/api/v1/predict")
@limiter.limit("20/minute")   # 20 requests per minute per IP
async def predict(request: Request, ...):
    ...

# For API key-based limiting (better for B2B):
def get_api_key(request: Request) -> str:
    return request.headers.get("X-API-KEY", get_remote_address(request))

limiter_by_key = Limiter(key_func=get_api_key)
""",
        "express_code": """
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 60 * 1000,  // 1 minute
    max: 20,
    message: { error: 'Rate limit exceeded' }
});
app.use('/api/predict', limiter);
"""
    },
    
    "SENSITIVE_PATH": {
        "title": "Remove or Restrict Exposed Paths",
        "effort": "1-2 hours",
        "priority": "CRITICAL",
        "fastapi_code": """
# 1. Ensure .env is in .gitignore — check:
cat .gitignore | grep .env   # should return ".env"

# 2. Remove debug/docs endpoints in production:
app = FastAPI(
    docs_url="/docs" if os.getenv("ENVIRONMENT") == "development" else None,
    redoc_url=None  # Remove ReDoc entirely
)

# 3. For Render: Environment variables go in dashboard, not .env files.
# Dashboard → your service → Environment → Add Environment Variable

# 4. Check git history for accidentally committed secrets:
# git log --all -p | grep -i "password\\|secret\\|api_key"
# If found: rotate credentials IMMEDIATELY, then use git-filter-repo to purge history
""",
        "general": "Use https://gitguardian.com (free) to scan your repository for historical secret leaks."
    },
    
    "DEPENDENCY": {
        "title": "Update Vulnerable Dependencies",
        "effort": "2-4 hours",
        "priority": "HIGH",
        "fastapi_code": """
# For Python — update specific packages:
pip install --upgrade package-name

# Check for vulnerabilities after updating:
pip install safety
safety check

# For automated monitoring — add to CI/CD:
# GitHub: Enable Dependabot in Settings → Security → Dependabot alerts
# This automatically opens PRs when vulnerabilities are found

# Pin versions in requirements.txt to avoid unexpected updates:
# fastapi==0.104.1  (not fastapi>=0.104.1)
""",
        "npm_code": """
# Update vulnerable npm packages:
npm audit fix

# For major version updates (may have breaking changes):
npm audit fix --force

# Add to CI/CD pipeline:
npm audit --audit-level=high   # Fails pipeline if HIGH/CRITICAL vulns exist
"""
    },
    
    "INFORMATION_DISCLOSURE": {
        "title": "Suppress Verbose Error Responses",
        "effort": "1 hour",
        "priority": "MEDIUM",
        "fastapi_code": """
# Add a global exception handler to main.py:
import logging
logger = logging.getLogger(__name__)

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log the full error internally — never lose the details
    logger.exception(f"Unhandled error on {request.method} {request.url}: {exc}")
    
    # In production, send only a generic message to the client
    if os.getenv("ENVIRONMENT") == "production":
        return JSONResponse(
            status_code=500,
            content={"error": "An internal error occurred."}
        )
    
    # In development, include the full traceback
    import traceback
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "traceback": traceback.format_exc()}
    )

# Remove version info from /health endpoint:
@app.get("/health")
async def health():
    # GOOD: minimal response
    return {"status": "ok"}
    # BAD: {"status": "ok", "version": "1.2.3", "python": "3.11.0", "dependencies": {...}}
"""
    }
}


@router.get("/findings/{finding_id}/defense")
def get_defense_for_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Get a specific, actionable defense recommendation for a finding.
    
    Returns the relevant code example based on the finding's attack family.
    This is what a developer opens when they want to know exactly how to fix something.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise NotFoundError("Finding", details={"id": finding_id})
    
    # Look up the playbook entry for this finding's attack family
    family_key = finding.attack_family.upper().replace(" ", "_")
    playbook_entry = DEFENSE_PLAYBOOK.get(family_key)
    
    if not playbook_entry:
        return {
            "finding_id": finding_id,
            "attack_family": finding.attack_family,
            "severity": finding.severity,
            "recommendation": finding.recommendation,
            "note": "No specific code example available for this attack family. Follow the recommendation above."
        }
    
    return {
        "finding_id": finding_id,
        "attack_family": finding.attack_family,
        "severity": finding.severity.value,
        "title": playbook_entry["title"],
        "effort": playbook_entry.get("effort"),
        "priority": playbook_entry.get("priority"),
        "description": finding.description,
        "recommendation": finding.recommendation,
        "code_examples": {
            k: v for k, v in playbook_entry.items()
            if k not in ("title", "effort", "priority")
        },
        "compliance_references": (finding.evidence or {}).get("compliance_references", [])
    }


@router.get("/clients/{client_id}/defenses")
def get_client_defenses(
    client_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Get all open defense items for a client, prioritised by severity.
    
    This is the developer's to-do list — ordered by what to fix first.
    """
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise NotFoundError("Client", details={"id": client_id})
    
    open_findings = db.query(Finding).filter(
        Finding.client_id == client_id,
        Finding.status == "open"
    ).all()
    
    # Build prioritised defense list
    defenses = []
    for finding in open_findings:
        family_key = finding.attack_family.upper().replace(" ", "_")
        playbook = DEFENSE_PLAYBOOK.get(family_key, {})
        
        defenses.append({
            "finding_id": finding.id,
            "attack_family": finding.attack_family,
            "severity": finding.severity.value,
            "title": finding.title,
            "estimated_effort": playbook.get("effort", "Unknown"),
            "has_code_example": family_key in DEFENSE_PLAYBOOK
        })
    
    # Sort: CRITICAL first, then HIGH, MEDIUM, LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    defenses.sort(key=lambda d: severity_order.get(d["severity"], 99))
    
    return {
        "client_id": client_id,
        "client_name": client.name,
        "open_items": len(defenses),
        "defenses": defenses
    }