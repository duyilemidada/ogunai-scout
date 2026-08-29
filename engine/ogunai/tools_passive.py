# engine/ogunai/tools_passive.py
"""
Passive Security Audit Tools for OgunAI

Everything in this file is OBSERVATIONAL.
No SQL injection payloads. No credential stuffing. No IDOR probing.
These tools read what the server already broadcasts and check known-good
lists against what's present.

The philosophy: a misconfigured server leaves visible signs everywhere.
You do not need to attack it to find them. You just need to know where to look.

Tool list:
- check_security_headers: Read HTTP response headers, score what's missing
- scan_sensitive_paths: GET common paths, check for 200s
- check_ssl_tls: Certificate expiry, TLS version, redirect to HTTPS
- check_dns_email_security: SPF, DMARC, MX records
- check_cors_policy: Test CORS with a spoofed Origin header
- check_rate_limiting: Send 15 requests, see if 429 appears
- check_information_disclosure: Version leakage in headers and error responses
- scan_dependencies: Check package list against OSV.dev vulnerability DB
- write_finding: Record a confirmed issue
"""

import requests
from datetime import datetime, timezone
import ssl
import socket
import json
import time
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────────────
# SHARED REQUEST HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _get(url: str, timeout: int = 10, headers: dict = None) -> Optional[requests.Response]:
    """
    Make a single GET request. Returns None on timeout or connection failure.
    
    We never raise here — every caller checks for None and handles gracefully.
    This prevents one unreachable endpoint from crashing the whole scan.
    """
    default_headers = {
        "User-Agent": "OgunAI-Audit/3.0 (security assessment; contact@ogunai.io)"
    }
    if headers:
        default_headers.update(headers)

    try:
        return requests.get(
            url,
            headers=default_headers,
            timeout=timeout,
            allow_redirects=False,  # We want to see redirects, not follow them silently
            verify=True             # SSL verification ON — we want to catch cert errors
        )
    except requests.exceptions.SSLError as e:
        # SSL error is itself a finding — we return a sentinel so callers know
        return {"ssl_error": str(e), "url": url}
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        return None

def _request(
    url: str,
    method: str = "GET",
    body: Optional[Dict] = None,
    extra_headers: Optional[Dict] = None,
    timeout: int = 10
) -> Optional[requests.Response]:
    """
    Make a request with any HTTP method.
    Used by method-aware rate limit probing so we can POST/PUT with real bodies.
    """
    default_headers = {
        "User-Agent": "OgunAI-Audit/3.0 (security assessment; contact@ogunai.io)",
        "Content-Type": "application/json"
    }
    if extra_headers:
        default_headers.update(extra_headers)

    try:
        kwargs = {
            "headers": default_headers,
            "timeout": timeout,
            "allow_redirects": False,
            "verify": True
        }
        if body and method.upper() in ("POST", "PUT", "PATCH"):
            kwargs["json"] = body

        return requests.request(method.upper(), url, **kwargs)
    except requests.exceptions.SSLError as e:
        return {"ssl_error": str(e), "url": url}
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        return None

# ─────────────────────────────────────────────────────────────────────────────
# TOOL 1: Security Headers
# ─────────────────────────────────────────────────────────────────────────────

def check_security_headers(base_url: str) -> Dict[str, Any]:
    """
    Read HTTP response headers and score which security headers are present.
    
    This is the most basic passive check — you hit the server's root endpoint
    and read what it sends back. A misconfigured server advertises its
    weaknesses in the headers of every single response it makes.
    
    No attacks. No payloads. Just reading.
    
    Args:
        base_url: Root URL of the target (e.g., "https://api.fraudshield.app")
    
    Returns:
        Dict with scored findings per header, overall severity, and summary
    """
    
    # Try root, then /health, then /api — take first that responds
    for path in ["/", "/health", "/api", "/api/v1"]:
        resp = _get(base_url.rstrip("/") + path)
        if resp and not isinstance(resp, dict) and resp.status_code < 500:
            break
    else:
        return {
            "error": "Server did not respond to any probe path",
            "severity": "INFO"
        }
    
    # Normalise header keys to lowercase for consistent lookup
    headers = {k.lower(): v for k, v in resp.headers.items()}
    
    # The full list of headers we check, with:
    # - what it does
    # - what attack class its absence enables
    # - what the recommended value is
    # - severity of missing it (MEDIUM or LOW)
    HEADER_SPECS = {
        "strict-transport-security": {
            "description": "Forces HTTPS. Prevents SSL stripping.",
            "attack_if_missing": "Man-in-the-middle: attacker on same network downgrades HTTPS to HTTP, reads all traffic including tokens.",
            "recommended": "max-age=31536000; includeSubDomains",
            "severity_if_missing": "HIGH",
            "should_be_present": True
        },
        "content-security-policy": {
            "description": "Controls which scripts the browser will execute.",
            "attack_if_missing": "XSS: if an injection point exists, attacker can run arbitrary JavaScript. Without CSP, there is no browser-level mitigation.",
            "recommended": "default-src 'self'; script-src 'self'",
            "severity_if_missing": "MEDIUM",
            "should_be_present": True
        },
        "x-frame-options": {
            "description": "Prevents your page being embedded in an iframe.",
            "attack_if_missing": "Clickjacking: attacker overlays your login form in an invisible iframe on their own page.",
            "recommended": "DENY",
            "severity_if_missing": "MEDIUM",
            "should_be_present": True
        },
        "x-content-type-options": {
            "description": "Prevents browser from MIME-sniffing response type.",
            "attack_if_missing": "MIME confusion: browser might execute an uploaded file as a script if content-type is wrong.",
            "recommended": "nosniff",
            "severity_if_missing": "LOW",
            "should_be_present": True
        },
        "referrer-policy": {
            "description": "Controls what URL is sent in the Referer header.",
            "attack_if_missing": "URL leakage: internal paths, session tokens in URLs, or user IDs can leak to third-party scripts via the Referer header.",
            "recommended": "no-referrer",
            "severity_if_missing": "LOW",
            "should_be_present": True
        },
        "permissions-policy": {
            "description": "Restricts browser feature access (camera, mic, location).",
            "attack_if_missing": "If XSS occurs, attacker script can request camera/microphone access without restrictions.",
            "recommended": "camera=(), microphone=(), geolocation=()",
            "severity_if_missing": "LOW",
            "should_be_present": True
        },
        # These should be ABSENT — their presence is the finding
        "x-powered-by": {
            "description": "Should be absent. Reveals framework and version.",
            "attack_if_missing": None,
            "attack_if_present": "Fingerprinting: 'X-Powered-By: Express 4.17.1' tells attacker exactly which CVEs apply. Remove with app.disable('x-powered-by').",
            "recommended": "ABSENT",
            "severity_if_present": "LOW",
            "should_be_present": False
        },
        "server": {
            "description": "Should be absent or generic. Reveals server software version.",
            "attack_if_missing": None,
            "attack_if_present": "Fingerprinting: 'Server: nginx/1.18.0' reveals exact version with known CVEs.",
            "recommended": "ABSENT or generic (e.g., 'Server: ogunai')",
            "severity_if_present": "LOW",
            "should_be_present": False
        }
    }
    
    results = []
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for header_name, spec in HEADER_SPECS.items():
        present = header_name in headers
        value = headers.get(header_name)
        
        if spec["should_be_present"]:
            # Header SHOULD be present
            if not present:
                sev = spec["severity_if_missing"]
                if sev == "HIGH": high_count += 1
                elif sev == "MEDIUM": medium_count += 1
                else: low_count += 1
                
                results.append({
                    "header": header_name,
                    "status": "MISSING",
                    "severity": sev,
                    "description": spec["description"],
                    "attack_enabled": spec["attack_if_missing"],
                    "recommended_value": spec["recommended"],
                    "current_value": None
                })
            else:
                results.append({
                    "header": header_name,
                    "status": "PRESENT",
                    "severity": "PASS",
                    "current_value": value
                })
        else:
            # Header should be ABSENT
            if present:
                sev = spec.get("severity_if_present", "LOW")
                low_count += 1
                results.append({
                    "header": header_name,
                    "status": "SHOULD_BE_ABSENT",
                    "severity": sev,
                    "description": spec["description"],
                    "attack_enabled": spec.get("attack_if_present"),
                    "current_value": value,
                    "recommended_value": spec["recommended"]
                })
            else:
                results.append({
                    "header": header_name,
                    "status": "CORRECTLY_ABSENT",
                    "severity": "PASS",
                    "current_value": None
                })
    
    overall = "HIGH" if high_count else "MEDIUM" if medium_count else "LOW" if low_count else "PASS"
    
    return {
        "url_checked": base_url,
        "headers_checked": len(HEADER_SPECS),
        "issues_found": high_count + medium_count + low_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "results": results,
        "overall_severity": overall
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 2: Sensitive Path Scan
# ─────────────────────────────────────────────────────────────────────────────

def scan_sensitive_paths(base_url: str, extra_paths: List[str] = None) -> Dict[str, Any]:
    """
    Check for publicly accessible sensitive files and directories.
    
    Simple GET requests to common paths. No attack payloads.
    A 200 from /.env means credentials are exposed to anyone on the internet.
    A 200 from /.git/config means the source code repository URL (sometimes
    with credentials) is publicly accessible.
    
    We check the response body for credential keywords — a 200 from /health
    that only returns {"status": "ok"} is fine; a 200 from /health that
    returns your database connection string is a critical finding.
    
    Args:
        base_url: Root URL
        extra_paths: Additional paths from client profile to check
    
    Returns:
        Dict with exposed paths and their severity
    """
    
    # Paths that real attackers check on every target
    # Organised by category for readability
    DEFAULT_PATHS = [
        # Credential files
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.staging",
        "/.env.backup",
        
        # Source control
        "/.git/config",
        "/.git/HEAD",
        "/.gitignore",
        
        # Backups
        "/backup.zip",
        "/backup.sql",
        "/backup.tar.gz",
        "/db.sql",
        "/database.sql",
        "/dump.sql",
        
        # Admin panels
        "/admin",
        "/admin/",
        "/admin/login",
        "/dashboard",
        "/superadmin",
        
        # API documentation (exposes full schema to attackers)
        "/api-docs",
        "/api/docs",
        "/swagger",
        "/swagger.json",
        "/swagger-ui.html",
        "/openapi.json",
        "/openapi.yaml",
        "/docs",
        "/redoc",
        
        # GraphQL (check if introspection is on)
        "/graphql",
        "/graphiql",
        
        # Monitoring (leaks internal metrics)
        "/metrics",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        
        # Debug endpoints
        "/debug",
        "/debug/vars",
        "/server-status",
        "/server-info",
        
        # Common framework paths
        "/phpinfo.php",
        "/info.php",
        "/.htaccess",
        "/web.config",
        "/config.json",
        "/config.yaml",
        "/config.yml",
        "/settings.json",
        "/application.properties",
        "/secrets.yaml",
    ]
    
    all_paths = list(set(DEFAULT_PATHS + (extra_paths or [])))
    
    # Keywords that indicate the response body contains actual credentials
    # A 200 from /health is normal — a 200 from /.env containing these is critical
    CREDENTIAL_KEYWORDS = [
        "password", "passwd", "secret", "api_key", "apikey",
        "mongodb://", "postgres://", "mysql://", "redis://",
        "aws_access_key", "aws_secret", "private_key",
        "-----begin", "token=", "key=", "credential",
        "database_url", "connection_string"
    ]
    
    exposed = []
    
    for path in all_paths:
        url = base_url.rstrip("/") + path
        resp = _get(url, timeout=8)
        
        if resp is None or isinstance(resp, dict):
            continue
        
        # We care about:
        # 200: Path exists and content is accessible
        # 403: Path exists but is blocked (could be bypassable, worth noting)
        # 301/302: Redirect (note the target — might redirect to exposed content)
        if resp.status_code not in (200, 403, 301, 302):
            continue
        
        # Check for credential keywords in response body
        body_lower = resp.text[:1000].lower()
        found_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in body_lower]
        has_credentials = len(found_keywords) > 0
        
        if resp.status_code == 200:
            severity = "CRITICAL" if has_credentials else "MEDIUM"
        elif resp.status_code == 403:
            severity = "LOW"  # Exists but blocked — lower priority
        else:
            severity = "LOW"  # Redirect
        
        exposed.append({
            "path": path,
            "url": url,
            "status_code": resp.status_code,
            "severity": severity,
            "has_credential_content": has_credentials,
            "credential_keywords_found": found_keywords,
            "content_preview": resp.text[:300] if resp.status_code == 200 else None,
            "content_type": resp.headers.get("Content-Type", "unknown")
        })
    
    critical = [e for e in exposed if e["severity"] == "CRITICAL"]
    medium = [e for e in exposed if e["severity"] == "MEDIUM"]
    
    return {
        "paths_checked": len(all_paths),
        "exposed_count": len(exposed),
        "critical_count": len(critical),
        "medium_count": len(medium),
        "exposed": exposed,
        "critical_exposures": critical,
        "overall_severity": "CRITICAL" if critical else "MEDIUM" if medium else "LOW" if exposed else "PASS"
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3: SSL/TLS Check
# ─────────────────────────────────────────────────────────────────────────────

def check_ssl_tls(base_url: str) -> Dict[str, Any]:
    """
    Check SSL certificate and TLS configuration.
    
    Checks:
    - Certificate expiry: an expired cert breaks trust and indicates poor ops hygiene
    - TLS version: TLS 1.0 and 1.1 are deprecated and have known vulnerabilities
    - Certificate issuer: self-signed certs fail browser trust checks
    - HTTP to HTTPS redirect: if HTTP is accessible without redirect, the whole
      point of HTTPS is undermined for anyone who types the URL without https://
    
    Uses Python's built-in ssl module — no third-party dependencies for this check.
    
    Args:
        base_url: URL including https:// scheme
    
    Returns:
        Dict with certificate details and TLS findings
    """
    
    parsed = urlparse(base_url)
    hostname = parsed.hostname
    port = parsed.port or 443
    
    findings = []
    cert_info = {}
    
    # ── Certificate Check ────────────────────────────────────────────
    try:
        # Create SSL context that will give us cert details
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate details
                cert = ssock.getpeercert()
                
                # TLS version used (we want 1.2 minimum, 1.3 ideal)
                tls_version = ssock.version()
                
                cert_info["tls_version"] = tls_version
                cert_info["cipher"] = ssock.cipher()
                
                # Certificate expiry
                # cert["notAfter"] format: "Jan  1 00:00:00 2026 GMT"
                
                expiry_str = cert.get("notAfter", "")
                if expiry_str:
                    expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y GMT")
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                    days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                    cert_info["expires"] = expiry_str
                    cert_info["days_until_expiry"] = days_until_expiry
                    
                    if days_until_expiry < 0:
                        findings.append({
                            "issue": "Certificate is expired",
                            "severity": "CRITICAL",
                            "detail": f"Expired {abs(days_until_expiry)} days ago on {expiry_str}",
                            "recommendation": "Renew immediately. Use Let's Encrypt with auto-renewal."
                        })
                    elif days_until_expiry < 14:
                        findings.append({
                            "issue": "Certificate expires very soon",
                            "severity": "HIGH",
                            "detail": f"Expires in {days_until_expiry} days on {expiry_str}",
                            "recommendation": "Renew now. Set up auto-renewal to prevent future incidents."
                        })
                    elif days_until_expiry < 30:
                        findings.append({
                            "issue": "Certificate expiring soon",
                            "severity": "MEDIUM",
                            "detail": f"Expires in {days_until_expiry} days",
                            "recommendation": "Schedule renewal. Enable auto-renewal."
                        })
                
                # TLS version check
                if tls_version in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "issue": f"Deprecated TLS version in use: {tls_version}",
                        "severity": "HIGH",
                        "detail": f"Server negotiated {tls_version} which is deprecated and has known vulnerabilities (POODLE, BEAST).",
                        "recommendation": "Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and 1.3."
                    })
                
                # Issuer check
                issuer = dict(x[0] for x in cert.get("issuer", []))
                cert_info["issuer"] = issuer.get("organizationName", "Unknown")
                cert_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                
                # Self-signed check: if issuer == subject, it's self-signed
                subject_org = dict(x[0] for x in cert.get("subject", [])).get("organizationName", "")
                if issuer.get("organizationName") == subject_org and subject_org:
                    findings.append({
                        "issue": "Self-signed certificate detected",
                        "severity": "MEDIUM",
                        "detail": "Self-signed certificates are not trusted by browsers and indicate non-production setup.",
                        "recommendation": "Use a certificate from a trusted CA. Let's Encrypt provides free certificates."
                    })
    
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "issue": "SSL certificate verification failed",
            "severity": "HIGH",
            "detail": str(e),
            "recommendation": "Ensure certificate is valid, not expired, and from a trusted CA."
        })
    except (socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        return {
            "error": f"Could not connect to {hostname}:{port}: {e}",
            "severity": "INFO"
        }
    
    # ── HTTP → HTTPS Redirect Check ──────────────────────────────────
    # Check if plain HTTP redirects to HTTPS
    # If not, users who type the URL without https:// are on an insecure connection
    try:
        http_url = f"http://{hostname}:{80 if port == 443 else port}"
        http_resp = requests.get(http_url, timeout=8, allow_redirects=False)
        
        if http_resp.status_code in (301, 302):
            location = http_resp.headers.get("Location", "")
            if location.startswith("https://"):
                cert_info["http_to_https_redirect"] = True
            else:
                cert_info["http_to_https_redirect"] = False
                findings.append({
                    "issue": "HTTP does not redirect to HTTPS",
                    "severity": "MEDIUM",
                    "detail": f"HTTP redirects to {location} instead of HTTPS version",
                    "recommendation": "Configure server to redirect all HTTP to HTTPS."
                })
        elif http_resp.status_code == 200:
            # HTTP served content without redirecting — bad
            cert_info["http_to_https_redirect"] = False
            findings.append({
                "issue": "HTTP endpoint serves content without redirecting to HTTPS",
                "severity": "HIGH",
                "detail": "Users connecting via HTTP receive unencrypted content with no redirect.",
                "recommendation": "Configure redirect: HTTP 301 → HTTPS for all requests."
            })
        else:
            cert_info["http_to_https_redirect"] = "unknown"
    
    except Exception:
        cert_info["http_to_https_redirect"] = "could_not_check"
    
    severity_levels = [f["severity"] for f in findings]
    overall = ("CRITICAL" if "CRITICAL" in severity_levels
               else "HIGH" if "HIGH" in severity_levels
               else "MEDIUM" if "MEDIUM" in severity_levels
               else "LOW" if "LOW" in severity_levels
               else "PASS")
    
    return {
        "hostname": hostname,
        "certificate": cert_info,
        "findings": findings,
        "overall_severity": overall
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 4: DNS and Email Security
# ─────────────────────────────────────────────────────────────────────────────
def check_dns_email_security(domain: str) -> Dict[str, Any]:
    """
    Check DNS records for email security configuration.

    CONTEXT-AWARE SEVERITY (Tier 1 improvement):
    If the domain has no MX records, it is not configured to send or receive
    email. SPF and DMARC are irrelevant for such domains — flagging them HIGH
    produces false positives (as seen on Render subdomains like
    fraudshield-xjgh.onrender.com). When MX is absent:
    - All email security findings are downgraded to LOW
    - A suppression_reason field explains why
    - The agent is instructed to note this in its write_finding call
    """
    try:
        import dns.resolver
    except ImportError:
        return {
            "error": "dnspython not installed. Run: pip install dnspython",
            "severity": "INFO"
        }

    findings = []
    records_found = {}

    # ── SPF Record ───────────────────────────────────────────────────
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        spf_records = [
            r.to_text().strip('"')
            for r in txt_records
            if "v=spf1" in r.to_text().lower()
        ]

        if spf_records:
            spf = spf_records[0]
            records_found["spf"] = spf

            if "+all" in spf:
                findings.append({
                    "issue": "SPF record allows all servers to send email (+all)",
                    "severity": "HIGH",
                    "detail": f"SPF ends with +all — any server can send email as {domain}.",
                    "recommendation": "Change to -all or ~all.",
                    "record": spf
                })
            elif "?all" in spf:
                findings.append({
                    "issue": "SPF record uses neutral policy (?all)",
                    "severity": "MEDIUM",
                    "detail": "Neutral policy provides no protection against spoofing.",
                    "recommendation": "Change to -all or ~all.",
                    "record": spf
                })
        else:
            findings.append({
                "issue": "No SPF record found",
                "severity": "HIGH",
                "detail": f"No TXT record starting with 'v=spf1' found for {domain}.",
                "recommendation": (
                    f"Add a TXT record for {domain}: "
                    "'v=spf1 include:yourmailprovider.com -all'."
                )
            })

    except dns.resolver.NXDOMAIN:
        return {"error": f"Domain {domain} does not exist", "severity": "INFO"}
    except dns.resolver.NoAnswer:
        findings.append({
            "issue": "No SPF record found",
            "severity": "HIGH",
            "detail": f"No TXT records at all found for {domain}.",
            "recommendation": "Add SPF record as described above."
        })
    except Exception as e:
        records_found["spf_error"] = str(e)

    # ── DMARC Record ─────────────────────────────────────────────────
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = [r.to_text().strip('"') for r in dmarc_records]

        if dmarc:
            dmarc_record = dmarc[0]
            records_found["dmarc"] = dmarc_record

            policy_match = re.search(r"p=(\w+)", dmarc_record)
            policy = policy_match.group(1) if policy_match else "none"

            if policy == "none":
                findings.append({
                    "issue": "DMARC policy is 'none' — no enforcement",
                    "severity": "MEDIUM",
                    "detail": "p=none means DMARC monitoring only. Spoofed emails are not blocked.",
                    "recommendation": "Change p=none to p=quarantine or p=reject.",
                    "record": dmarc_record
                })
        else:
            findings.append({
                "issue": "No DMARC record found",
                "severity": "HIGH",
                "detail": f"No DMARC record at _dmarc.{domain}.",
                "recommendation": (
                    f"Add TXT record for _dmarc.{domain}: "
                    "'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com'"
                )
            })

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        findings.append({
            "issue": "No DMARC record found",
            "severity": "HIGH",
            "detail": f"_dmarc.{domain} does not exist.",
            "recommendation": (
                f"Add TXT record for _dmarc.{domain}: "
                "'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com'"
            )
        })
    except Exception as e:
        records_found["dmarc_error"] = str(e)

    # ── MX Records ───────────────────────────────────────────────────
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        records_found["mx"] = [r.to_text() for r in mx_records]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        records_found["mx"] = []
    except Exception:
        records_found["mx"] = []

    # ── CONTEXT-AWARE SEVERITY SUPPRESSION ───────────────────────────
    # If no MX records exist, this domain is not configured to send email.
    # SPF/DMARC findings are not applicable — downgrade all to LOW and
    # add a suppression_reason so the agent can report this accurately
    # instead of writing misleading HIGH findings.
    has_mx = bool(records_found.get("mx"))

    if not has_mx:
        suppression_reason = (
            f"Domain '{domain}' has no MX records and does not appear to send "
            f"or receive email. SPF and DMARC are only required for domains that "
            f"send email. This is common for API subdomains hosted on platforms "
            f"like Render, Railway, or Fly.io. If this domain DOES send email via "
            f"a third-party provider (SendGrid, Mailgun etc.), MX records should "
            f"be added and this finding re-evaluated."
        )
        for finding in findings:
            if finding.get("severity") in ("HIGH", "MEDIUM"):
                finding["original_severity"] = finding["severity"]
                finding["severity"] = "LOW"
                finding["suppression_reason"] = suppression_reason

    severity_levels = [f["severity"] for f in findings]
    overall = (
        "HIGH" if "HIGH" in severity_levels
        else "MEDIUM" if "MEDIUM" in severity_levels
        else "LOW" if severity_levels
        else "PASS"
    )

    return {
        "domain": domain,
        "has_mx_records": has_mx,
        "records_found": records_found,
        "findings": findings,
        "overall_severity": overall,
        "severity_suppressed": not has_mx,
        "summary": (
            f"SPF: {'✓' if 'spf' in records_found else '✗'} | "
            f"DMARC: {'✓' if 'dmarc' in records_found else '✗'} | "
            f"MX: {'✓' if has_mx else '✗ (no email configured)'}"
        )
    }


def fetch_openapi_schema(base_url: str) -> Dict[str, Any]:
    """
    Fetch and parse the OpenAPI/Swagger schema from common discovery paths.

    This is the Tier 1/3 improvement that makes Scout schema-aware.
    Instead of guessing at endpoints and HTTP methods, the agent can read
    the schema and know exactly what each endpoint requires before probing it.

    This directly enables method-aware rate limit probing:
    - Without schema: sends GET to all endpoints (misses POST-only routes)
    - With schema: sends POST with correct body to /predict, GET to /health, etc.

    The schema exposure itself may be a finding — /openapi.json publicly
    accessible gives attackers a complete map of your API. The agent decides
    whether to write that finding based on context (dev vs prod, sensitivity).

    Returns:
        Dict with endpoint list, methods, auth requirements, and schema URL.
        endpoints is a list of {path, method, summary, requires_auth, request_body}
    """
    schema_paths = [
        "/openapi.json",
        "/openapi.yaml",
        "/swagger.json",
        "/swagger.yaml",
        "/api-docs",
        "/api/v1/openapi.json",
        "/api/docs/openapi.json",
        "/v1/openapi.json",
    ]

    for path in schema_paths:
        url = base_url.rstrip("/") + path
        resp = _get(url, timeout=10)

        if not resp or isinstance(resp, dict) or resp.status_code != 200:
            continue

        try:
            if path.endswith((".yaml", ".yml")):
                try:
                    import yaml
                    schema = yaml.safe_load(resp.text)
                except ImportError:
                    # Try JSON parse as fallback
                    schema = resp.json()
            else:
                schema = resp.json()

            if not isinstance(schema, dict):
                continue

            # Validate it looks like OpenAPI
            if not any(k in schema for k in ("paths", "openapi", "swagger", "info")):
                continue

            # Extract structured endpoint information
            endpoints = []
            paths_obj = schema.get("paths", {})
            global_security = bool(schema.get("security"))

            for endpoint_path, methods_obj in paths_obj.items():
                if not isinstance(methods_obj, dict):
                    continue
                for method, details in methods_obj.items():
                    if method.lower() not in ("get", "post", "put", "patch", "delete", "options"):
                        continue
                    if not isinstance(details, dict):
                        continue

                    # Determine auth requirement
                    endpoint_security = details.get("security")
                    requires_auth = bool(
                        global_security or
                        (endpoint_security is not None and endpoint_security != [])
                    )

                    # Extract request body schema for POST/PUT/PATCH probing
                    body_schema = None
                    request_body = details.get("requestBody", {})
                    if request_body:
                        content = request_body.get("content", {})
                        json_schema = content.get("application/json", {}).get("schema", {})
                        if json_schema:
                            # Build a minimal example body from required fields
                            required = json_schema.get("required", [])
                            props = json_schema.get("properties", {})
                            body_schema = {
                                "required_fields": required,
                                "properties": {
                                    k: v.get("type", "string")
                                    for k, v in props.items()
                                    if k in required
                                } if required else {}
                            }

                    endpoints.append({
                        "path": endpoint_path,
                        "method": method.upper(),
                        "summary": details.get("summary", ""),
                        "requires_auth": requires_auth,
                        "has_request_body": bool(request_body),
                        "body_schema": body_schema,
                        "tags": details.get("tags", []),
                    })

            # Sort: most important endpoints first
            # PUT auth/predict-style endpoints at top
            def endpoint_priority(ep):
                path_lower = ep["path"].lower()
                if any(w in path_lower for w in ("predict", "transaction", "auth", "login")):
                    return 0
                if any(w in path_lower for w in ("upload", "payment", "transfer")):
                    return 1
                return 2

            endpoints.sort(key=endpoint_priority)

            return {
                "schema_found": True,
                "schema_url": url,
                "api_title": schema.get("info", {}).get("title", "Unknown"),
                "api_version": schema.get("info", {}).get("version", ""),
                "openapi_version": schema.get("openapi") or schema.get("swagger", ""),
                "endpoint_count": len(endpoints),
                "endpoints": endpoints[:40],  # Cap at 40 — beyond this the context bloats
                "severity": "INFO",
                "note": (
                    f"Schema found at {url}. "
                    f"Agent should use endpoint method/body info for accurate probing. "
                    f"Public schema exposure may be a finding if this is production."
                )
            }

        except Exception as e:
            # This path didn't parse — try next
            continue

    # Nothing found
    return {
        "schema_found": False,
        "schema_url": None,
        "endpoints": [],
        "endpoint_count": 0,
        "severity": "INFO",
        "note": (
            "No OpenAPI schema found at common paths. "
            "Agent will use generic endpoint probing. "
            "If the target has API docs at a non-standard path, "
            "check manually and add to the client profile."
        )
    }

# ─────────────────────────────────────────────────────────────────────────────
# TOOL 5: CORS Policy Check
# ─────────────────────────────────────────────────────────────────────────────

def check_cors_policy(base_url: str, api_endpoints: List[str] = None) -> Dict[str, Any]:
    """
    Check Cross-Origin Resource Sharing policy on API endpoints.
    
    CORS controls which websites can make requests to your API from
    a user's browser. A wildcard CORS policy (Access-Control-Allow-Origin: *)
    means any website can call your API using your users' credentials.
    
    The most dangerous combination:
    - Access-Control-Allow-Origin: *
    - Access-Control-Allow-Credentials: true
    
    This means: any website can call your API as the logged-in user.
    Attacker hosts evil.com, user visits it, evil.com silently makes
    API calls to your system with the user's session.
    
    We test by sending requests with a spoofed Origin header.
    
    Args:
        base_url: Root URL
        api_endpoints: Specific endpoints to check (defaults to common ones)
    
    Returns:
        Dict with CORS policy findings per endpoint
    """
    
    endpoints_to_check = api_endpoints or [
        "/",
        "/api/v1",
        "/api/v1/predict",
        "/api/v1/transactions",
        "/health",
    ]
    
    # We test with an obviously-malicious origin
    # If the server reflects this back in Access-Control-Allow-Origin, it's misconfigured
    EVIL_ORIGIN = "https://evil-attacker-site.example.com"
    
    findings = []
    endpoint_results = []
    
    for endpoint in endpoints_to_check:
        url = base_url.rstrip("/") + endpoint
        
        resp = _get(url, headers={"Origin": EVIL_ORIGIN})
        
        if resp is None or isinstance(resp, dict):
            continue
        
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        
        result = {
            "endpoint": endpoint,
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "access_control_allow_methods": acam
        }
        
        # Wildcard + Credentials is the critical combination
        if acao == "*" and acac.lower() == "true":
            result["severity"] = "CRITICAL"
            findings.append({
                "endpoint": endpoint,
                "issue": "Wildcard CORS with credentials allowed",
                "severity": "CRITICAL",
                "detail": "Access-Control-Allow-Origin: * combined with Allow-Credentials: true means any website can call your API using the user's session.",
                "recommendation": "Never combine wildcard origin with credentials. List specific allowed origins explicitly."
            })
        
        # Wildcard without credentials — lower risk but still bad for auth endpoints
        elif acao == "*":
            result["severity"] = "LOW"
            # Only flag this for sensitive-looking endpoints
            if any(word in endpoint for word in ["auth", "predict", "transactions", "users"]):
                findings.append({
                    "endpoint": endpoint,
                    "issue": "Wildcard CORS on sensitive endpoint",
                    "severity": "MEDIUM",
                    "detail": f"Wildcard CORS allows any website to read responses from {endpoint}.",
                    "recommendation": "Restrict to specific frontend domains."
                })
        
        # Server reflects the evil origin back — misconfigured wildcard
        elif acao == EVIL_ORIGIN:
            result["severity"] = "HIGH"
            findings.append({
                "endpoint": endpoint,
                "issue": "CORS reflects arbitrary Origin header",
                "severity": "HIGH",
                "detail": "Server reflects any Origin back as allowed — effectively a wildcard.",
                "recommendation": "Maintain an explicit allow-list of origins. Do not use request.headers.origin directly."
            })
        
        else:
            result["severity"] = "PASS"
        
        endpoint_results.append(result)
    
    severity_levels = [f["severity"] for f in findings]
    overall = ("CRITICAL" if "CRITICAL" in severity_levels
               else "HIGH" if "HIGH" in severity_levels
               else "MEDIUM" if "MEDIUM" in severity_levels
               else "PASS")
    
    return {
        "endpoints_checked": len(endpoints_to_check),
        "endpoint_results": endpoint_results,
        "findings": findings,
        "overall_severity": overall
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 6: Rate Limiting Detection
# ─────────────────────────────────────────────────────────────────────────────
def check_rate_limiting(
    base_url: str,
    endpoint: str = "/api/v1/predict",
    method: str = "GET",
    body: Optional[Dict] = None,
    auth_header: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Check if the API enforces rate limiting on a specific endpoint.

    METHOD-AWARE (Tier 1/2 improvement):
    The original implementation sent GET requests to all endpoints.
    This missed rate limiters on POST-only routes because the server
    returns 405 Method Not Allowed — the limiter never activates.

    This version accepts the correct HTTP method and body. The agent
    should call fetch_openapi_schema first, then pass the correct method:

        check_rate_limiting(
            base_url="https://api.example.com",
            endpoint="/api/v1/predict",
            method="POST",
            body={"amount": 100, "customer_id": "test"}
        )

    If the endpoint requires auth (requires_auth=True in schema), the agent
    should note that in the finding: rate limit detection is approximate
    because unauthenticated requests are rejected before hitting the limiter.

    Args:
        base_url: Root URL
        endpoint: Endpoint path to probe
        method: HTTP method (GET, POST, PUT, etc.) — use schema info
        body: Request body for POST/PUT/PATCH (use minimal valid body)
        auth_header: Optional Authorization header value for authenticated probing

    Returns:
        Dict with rate limit detection result, including method used and
        a confidence note if probing was unauthenticated on an auth-required route.
    """
    url = base_url.rstrip("/") + endpoint
    responses = []

    extra_headers = {}
    if auth_header:
        extra_headers["Authorization"] = auth_header

    # First probe: OPTIONS to discover what the endpoint actually accepts
    # This helps detect 405 responses before we waste 15 requests
    options_resp = _request(url, method="OPTIONS", timeout=8)
    allowed_methods = []
    if options_resp and not isinstance(options_resp, dict):
        allow_header = options_resp.headers.get("Allow", "")
        if allow_header:
            allowed_methods = [m.strip().upper() for m in allow_header.split(",")]

    # If caller specified GET but server only allows POST, note this
    method_mismatch = (
        allowed_methods and
        method.upper() not in allowed_methods and
        method.upper() != "GET"  # GET mismatches are less concerning
    )

    for i in range(15):
        resp = _request(
            url,
            method=method,
            body=body,
            extra_headers=extra_headers,
            timeout=8
        )

        if resp is None or isinstance(resp, dict):
            break

        resp_data = {
            "attempt": i + 1,
            "status_code": resp.status_code,
            "has_rate_limit_headers": (
                "x-ratelimit-remaining" in resp.headers or
                "retry-after" in resp.headers or
                "x-rate-limit" in resp.headers or
                "ratelimit-limit" in resp.headers
            )
        }
        responses.append(resp_data)

        if resp.status_code == 429:
            # Rate limiting kicked in — correct behaviour
            break

        time.sleep(0.3)

    if not responses:
        return {
            "endpoint": endpoint,
            "method_used": method,
            "requests_sent": 0,
            "rate_limited": False,
            "severity": "INFO",
            "detail": "Endpoint did not respond to any probe requests.",
            "recommendation": "Verify the endpoint is reachable and the URL is correct."
        }

    status_codes = [r["status_code"] for r in responses]
    rate_limited = 429 in status_codes
    has_rl_headers = any(r["has_rate_limit_headers"] for r in responses)

    # Detect if all responses are auth errors (403/401/405) — probe was invalid
    auth_blocked = all(s in (401, 403) for s in status_codes)
    method_blocked = all(s == 405 for s in status_codes)

    # Build confidence note
    confidence_note = None
    if method_blocked:
        confidence_note = (
            f"All {len(responses)} requests returned 405 Method Not Allowed. "
            f"The endpoint may only accept {allowed_methods or 'a different method'}. "
            f"Rate limit detection is unreliable — use the correct HTTP method from the schema."
        )
    elif auth_blocked:
        confidence_note = (
            f"All {len(responses)} requests returned 401/403. "
            f"This endpoint requires authentication. "
            f"Rate limit detection is unreliable without valid credentials — "
            f"the auth check fires before the rate limiter."
        )
    elif method_mismatch:
        confidence_note = (
            f"Probed with {method} but server allows: {', '.join(allowed_methods)}. "
            f"Rate limit result may be inaccurate."
        )

    if rate_limited:
        severity = "PASS"
        detail = f"Rate limiting detected at attempt {status_codes.index(429) + 1}."
        recommendation = "Rate limiting is active."
    elif has_rl_headers:
        severity = "PASS"
        detail = "Rate limit headers present — rate limiting is configured."
        recommendation = "Rate limiting appears configured."
    elif method_blocked or auth_blocked:
        # Can't conclude rate limiting is absent if we never reached the endpoint logic
        severity = "INFO"
        detail = confidence_note or "Rate limit could not be assessed due to method/auth block."
        recommendation = (
            "Re-test with the correct HTTP method and a valid authentication token "
            "to get an accurate rate limit assessment."
        )
    else:
        severity = "HIGH"
        detail = (
            f"Sent {len(responses)} {method} requests to {endpoint} "
            f"without triggering rate limiting."
        )
        recommendation = (
            "Implement rate limiting on this endpoint. "
            "For FastAPI: use slowapi. For Express: use express-rate-limit. "
            "Recommended: max 20 requests per minute per API key on sensitive endpoints."
        )

    return {
        "endpoint": endpoint,
        "method_used": method,
        "allowed_methods": allowed_methods,
        "requests_sent": len(responses),
        "rate_limited": rate_limited,
        "has_rate_limit_headers": has_rl_headers,
        "status_codes_seen": list(set(status_codes)),
        "auth_blocked": auth_blocked,
        "method_blocked": method_blocked,
        "confidence_note": confidence_note,
        "responses": responses,
        "severity": severity,
        "detail": detail,
        "recommendation": recommendation
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 7: Information Disclosure Check
# ─────────────────────────────────────────────────────────────────────────────

def check_information_disclosure(base_url: str) -> Dict[str, Any]:
    """
    Check what internal information the server leaks in responses.
    
    Two approaches:
    1. Check the /health or /version endpoint for version strings
    2. Send a request with a clearly malformed path to trigger an error,
       then check if the error response contains stack traces or internal paths
    
    We are NOT injecting payloads. We are sending:
    - A deliberately invalid path (e.g., /api/v1/NOTAREALUSERNAMEEVER)
    - A request the server will reject (wrong content-type)
    
    The goal is to see what the error handler reveals.
    
    Args:
        base_url: Root URL
    
    Returns:
        Dict with disclosure findings
    """
    
    findings = []
    evidence = {}
    
    # ── Version endpoint check ────────────────────────────────────────
    for path in ["/health", "/version", "/api/version", "/api/v1/version", "/"]:
        resp = _get(base_url.rstrip("/") + path)
        if resp and not isinstance(resp, dict) and resp.status_code == 200:
            body = resp.text[:1000]
            evidence[f"response_{path}"] = body[:200]
            
            # Look for version strings in the response
            version_patterns = [
                r'\d+\.\d+\.\d+',          # Semver: 4.17.1
                r'"version"\s*:\s*"[^"]+"', # JSON version field
                r'node\.js[^"]*\d+',        # Node.js version
                r'python[^"]*\d+',          # Python version
                r'uvicorn[^"]*\d+',         # Uvicorn version
            ]
            
            for pattern in version_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    findings.append({
                        "issue": "Version information disclosed in response",
                        "severity": "LOW",
                        "detail": f"Found version strings at {path}: {matches[:3]}",
                        "recommendation": "Remove version strings from public-facing health endpoints."
                    })
                    break
    
    # ── Error handler check ───────────────────────────────────────────
    # Send a request to a path that clearly doesn't exist
    # A good error handler returns: {"error": "Not found"}
    # A bad error handler returns the full stack trace
    non_existent_path = "/api/v1/OGUNAI_AUDIT_PATH_THAT_DOES_NOT_EXIST_12345"
    resp = _get(base_url.rstrip("/") + non_existent_path)
    
    if resp and not isinstance(resp, dict):
        body = resp.text[:2000]
        evidence["error_response"] = body[:500]
        
        # Stack trace indicators
        stack_trace_indicators = [
            "traceback", "stack trace", "at line", "file \"", ".py\", line",
            "error in", "exception in", "internal server error",
            "node_modules", "at Object.", "at Function.",  # Node.js stack
            "raise ", "in <module>",  # Python
        ]
        
        found_indicators = [ind for ind in stack_trace_indicators if ind.lower() in body.lower()]
        
        if found_indicators:
            findings.append({
                "issue": "Stack trace or internal path exposed in error response",
                "severity": "MEDIUM",
                "detail": f"Error response at {non_existent_path} contains internal information: {found_indicators[:3]}",
                "recommendation": (
                    "In production, return only generic error messages. "
                    "Log full errors internally. "
                    "FastAPI: use custom exception handlers that return {\"error\": \"Internal error\"} only. "
                    "Express: app.use((err, req, res, next) => res.status(500).json({error: 'Internal error'}))."
                ),
                "evidence": body[:300]
            })
        
        # Check if the response reveals the framework
        framework_leaks = {
            "fastapi": "FastAPI detected",
            "express": "Express.js detected",
            "django": "Django detected",
            "flask": "Flask detected",
            "spring": "Spring Boot detected"
        }
        for keyword, label in framework_leaks.items():
            if keyword in body.lower():
                findings.append({
                    "issue": f"Framework fingerprinting via error response",
                    "severity": "LOW",
                    "detail": f"Error response reveals {label} — attackers can target framework-specific CVEs.",
                    "recommendation": "Return generic error messages in production."
                })
                break
    
    severity_levels = [f["severity"] for f in findings]
    overall = ("HIGH" if "HIGH" in severity_levels
               else "MEDIUM" if "MEDIUM" in severity_levels
               else "LOW" if findings
               else "PASS")
    
    return {
        "findings": findings,
        "evidence_collected": list(evidence.keys()),
        "overall_severity": overall
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 8: Dependency Vulnerability Scan
# ─────────────────────────────────────────────────────────────────────────────

def scan_dependencies(
    requirements_text: str,
    ecosystem: str = "PyPI"
) -> Dict[str, Any]:
    """
    Check a requirements.txt or package.json against the OSV vulnerability database.
    
    OSV (Open Source Vulnerabilities) is Google's free vulnerability database
    covering PyPI, npm, Maven, Go, and more. The API is free, no key needed.
    
    This is completely passive — we are not running the packages, not doing
    static analysis. We are just checking version numbers against a list
    of known-vulnerable versions.
    
    To use: ask the client to paste their requirements.txt content.
    You store it as a string in their profile and run this check.
    
    Args:
        requirements_text: Contents of requirements.txt or package.json as string
        ecosystem: "PyPI" for Python, "npm" for Node.js
    
    Returns:
        Dict with vulnerable packages found and CVE details
    """
    
    # ── Parse requirements ────────────────────────────────────────────
    packages = []
    
    if ecosystem == "PyPI":
        # Parse requirements.txt format: package==version or package>=version
        for line in requirements_text.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Match: package==1.2.3 or package>=1.2.3 or package~=1.2.3
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*[=~><!]+\s*([0-9][^\s;#]*)", line)
            if match:
                packages.append({
                    "name": match.group(1),
                    "version": match.group(2).strip(),
                    "ecosystem": "PyPI"
                })
    
    elif ecosystem == "npm":
        # Parse package.json — extract dependencies
        try:
            pkg_data = json.loads(requirements_text)
            for section in ["dependencies", "devDependencies"]:
                for name, version in pkg_data.get(section, {}).items():
                    # Strip ^ ~ from version strings
                    clean_version = re.sub(r"[^\d.]", "", version)
                    if clean_version:
                        packages.append({
                            "name": name,
                            "version": clean_version,
                            "ecosystem": "npm"
                        })
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON in package.json: {e}", "severity": "INFO"}
    
    if not packages:
        return {"error": "No packages parsed from input", "severity": "INFO"}
    
    # ── Query OSV API ─────────────────────────────────────────────────
    # OSV batch query: POST https://api.osv.dev/v1/querybatch
    # Supports up to 1000 queries per batch
    
    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    
    queries = [
        {
            "version": pkg["version"],
            "package": {
                "name": pkg["name"],
                "ecosystem": pkg["ecosystem"]
            }
        }
        for pkg in packages
    ]
    
    try:
        osv_response = requests.post(
            OSV_BATCH_URL,
            json={"queries": queries},
            timeout=30,
            headers={"Content-Type": "application/json"}
        )
        
        if osv_response.status_code != 200:
            return {
                "error": f"OSV API returned {osv_response.status_code}",
                "severity": "INFO"
            }
        
        osv_data = osv_response.json()
        results = osv_data.get("results", [])
    
    except requests.exceptions.Timeout:
        return {"error": "OSV API request timed out", "severity": "INFO"}
    except Exception as e:
        return {"error": f"OSV API error: {e}", "severity": "INFO"}
    
    # ── Process results ───────────────────────────────────────────────
    vulnerable_packages = []
    
    for i, result in enumerate(results):
        vulns = result.get("vulns", [])
        if not vulns:
            continue
        
        pkg = packages[i]
        pkg_vulns = []
        
        for vuln in vulns:
            severity = "MEDIUM"  # Default
            
            # Extract CVSS severity if available
            for severity_info in vuln.get("severity", []):
                if "score" in severity_info:
                    score = float(severity_info["score"])
                    if score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    break
            
            pkg_vulns.append({
                "id": vuln.get("id", "Unknown"),
                "summary": vuln.get("summary", "No description"),
                "severity": severity,
                "details": vuln.get("details", "")[:200],
                "references": [ref.get("url") for ref in vuln.get("references", [])[:3]]
            })
        
        if pkg_vulns:
            # Highest severity for this package
            pkg_severity = max(
                pkg_vulns,
                key=lambda v: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(v["severity"], 0)
            )["severity"]
            
            vulnerable_packages.append({
                "package": pkg["name"],
                "version": pkg["version"],
                "ecosystem": pkg["ecosystem"],
                "vulnerability_count": len(pkg_vulns),
                "highest_severity": pkg_severity,
                "vulnerabilities": pkg_vulns,
                "recommendation": f"Update {pkg['name']} to the latest version. Check https://pypi.org/project/{pkg['name']}/ for the current release."
            })
    
    critical_count = sum(1 for p in vulnerable_packages if p["highest_severity"] == "CRITICAL")
    high_count = sum(1 for p in vulnerable_packages if p["highest_severity"] == "HIGH")
    
    return {
        "packages_scanned": len(packages),
        "vulnerable_packages": len(vulnerable_packages),
        "critical_count": critical_count,
        "high_count": high_count,
        "results": vulnerable_packages,
        "overall_severity": (
            "CRITICAL" if critical_count > 0
            else "HIGH" if high_count > 0
            else "MEDIUM" if vulnerable_packages
            else "PASS"
        ),
        "osv_api_used": "https://api.osv.dev"
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 9: Write Finding
# ─────────────────────────────────────────────────────────────────────────────

def write_finding(
    attack_family: str,
    severity: str,
    title: str,
    description: str,
    evidence: Dict[str, Any],
    recommendation: str,
    endpoint: str = "",
    compliance_refs: List[str] = None,
    confidence: str = "medium",
) -> Dict[str, Any]:
    """
    Record a confirmed finding from the audit.

    CONFIDENCE FIELD (Tier 1/4 improvement):
    Adds an honest signal about how certain the finding is.
    This prevents over-reporting and builds client trust.

    confidence values:
    - "high":   Direct evidence in server response (e.g., header is actually missing,
                credential keyword found in body, wildcard CORS confirmed in response).
                Use when the finding is definitively confirmed by the tool output.

    - "medium": Strong indicator but not 100% confirmed. Default for most findings.
                Use when the tool result clearly suggests an issue but indirect evidence.
                Example: rate limiter not triggered in unauthenticated probe (may be
                auth-gated, not absent).

    - "low":    Possible issue but significant uncertainty. Use when:
                - Rate limiting probe was blocked by auth/method mismatch
                - SPF/DMARC finding on a domain with no MX (already suppressed but
                  still worth noting the uncertainty)
                - Sensitive path returns 403 (exists but blocked — may be intentional)
                - Any finding where the evidence is circumstantial

    The confidence field appears in the report and helps developers prioritise:
    high-confidence findings get fixed immediately, low-confidence findings
    get investigated before remediation.
    """
    # Validate confidence value
    valid_confidences = ("high", "medium", "low")
    if confidence not in valid_confidences:
        confidence = "medium"

    # Auto-map compliance references based on attack family
    COMPLIANCE_MAPPING = {
        "HEADER_SECURITY": [
            "CBN Cybersecurity Framework — Application Security (AS-3)",
            "NDPR Article 24 — Technical measures for data protection",
            "ISO 27001 A.14.1.2 — Securing application services"
        ],
        "SSL_TLS": [
            "CBN Cybersecurity Framework — Network Security (NS-7)",
            "NDPR Article 24 — Appropriate technical measures",
            "PCI DSS 4.2 — Protect PAN with strong cryptography"
        ],
        "SENSITIVE_PATH": [
            "CBN Cybersecurity Framework — Application Security (AS-1)",
            "NDPR Article 24 — Ensuring ongoing confidentiality",
            "OWASP Top 10 — A05: Security Misconfiguration"
        ],
        "DNS_EMAIL": [
            "CBN Cybersecurity Framework — Identity & Access Management (IAM2)",
            "NDPR Article 24 — Protection against unauthorised access",
            "ISO 27001 A.13.2.3 — Electronic messaging"
        ],
        "EMAIL_SPOOFING": [
            "CBN Cybersecurity Framework — Identity & Access Management (IAM2)",
            "NDPR Article 24 — Protection against unauthorised access",
        ],
        "CORS": [
            "CBN Cybersecurity Framework — Application Security (AS-4)",
            "NDPR Article 24 — Technical measures for data protection"
        ],
        "RATE_LIMIT": [
            "CBN Cybersecurity Framework — Application Security (AS-5)",
            "NDPR Article 24 — Ensuring availability of processing"
        ],
        "BRUTE_FORCE": [
            "CBN Cybersecurity Framework — Application Security (AS-5)",
            "NDPR Article 24 — Ensuring availability of processing"
        ],
        "DENIAL_OF_SERVICE": [
            "CBN Cybersecurity Framework — Application Security (AS-5)",
            "NDPR Article 24 — Ensuring availability of processing"
        ],
        "DEPENDENCY": [
            "CBN Cybersecurity Framework — Vulnerability Management (VM-2)",
            "NDPR Article 24 — Technical measures",
            "PCI DSS 6.3.3 — All software components protected from known vulnerabilities"
        ],
        "INFORMATION_DISCLOSURE": [
            "CBN Cybersecurity Framework — Application Security (AS-2)",
            "NDPR Article 24 — Ensuring confidentiality",
            "OWASP Top 10 — A05: Security Misconfiguration"
        ],
    }

    # Normalise family key for lookup (handles "Email Spoofing" → "EMAIL_SPOOFING")
    family_key = attack_family.upper().replace(" ", "_")
    auto_refs = COMPLIANCE_MAPPING.get(family_key, [])
    final_refs = compliance_refs or auto_refs

    finding = {
        "attack_family": attack_family,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "endpoint": endpoint,
        "compliance_references": final_refs,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    print(f"[FINDING] {severity} [{confidence} confidence]: {title}")
    return finding

def audit_orm_safety(code_snippet: str) -> Dict[str, Any]:
    """
    Scan code snippet for dangerous ORM patterns like raw SQL concatenation.
    Useful if the client provides access to their codebase.
    """
    import re
    findings = []
    
    dangerous_patterns = [
        (r"execute\(.*?f['\"]", "Raw SQL with f-string (SQLi risk)"),
        (r"\.format\(.*?\)", "String formatting in query (SQLi risk)"),
        (r"%s.*%.*", "String interpolation in query (SQLi risk)")
    ]
    
    for pattern, desc in dangerous_patterns:
        if re.search(pattern, code_snippet):
            findings.append({
                "issue": f"Unsafe ORM pattern: {desc}",
                "severity": "HIGH",
                "detail": f"Matched pattern: {pattern}",
                "recommendation": "Use parameterized queries or ORM safe methods."
            })
            
    return {
        "patterns_checked": len(dangerous_patterns),
        "findings": findings,
        "severity": "HIGH" if findings else "PASS"
    }