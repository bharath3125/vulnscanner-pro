import httpx
from app.models.scan_models import VulnerabilityFinding, Severity

# Common weak endpoints or issues
BROKEN_AUTH_CHECKS = [
    {
        "endpoint": "", # Root
        "check": lambda h: "Set-Cookie" in h and "HttpOnly" not in h["Set-Cookie"],
        "name": "Missing HttpOnly Flag on Cookie",
        "description": "Session cookies without the HttpOnly flag can be accessed by JavaScript.",
        "severity": Severity.MEDIUM
    },
    {
        "endpoint": "", # Root
        "check": lambda h: "Set-Cookie" in h and "Secure" not in h["Set-Cookie"],
        "name": "Missing Secure Flag on Cookie",
        "description": "Session cookies without the Secure flag can be transmitted over unencrypted HTTP.",
        "severity": Severity.MEDIUM
    },
    {
        "endpoint": "admin/",
        "check": lambda r: r.status_code == 200 and "login" not in r.text.lower(),
        "name": "Unprotected Admin Panel",
        "description": "Admin panel appears accessible without authentication.",
        "severity": Severity.CRITICAL
    }
]

async def scan_broken_auth(target_url: str) -> list[VulnerabilityFinding]:
    findings = []
    
    base_url = target_url.rstrip("/")
    
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        # Check Cookies on Root
        try:
            response = await client.get(target_url)
            headers = response.headers
            
            # Check Cookie Flags
            if "Set-Cookie" in headers:
                cookie_val = headers["Set-Cookie"]
                if "HttpOnly" not in cookie_val:
                     findings.append(VulnerabilityFinding(
                        name="Missing HttpOnly Flag on Cookie",
                        description="Session cookies are accessible to JavaScript (risk of XSS stealing session).",
                        severity=Severity.MEDIUM,
                        url=target_url,
                        evidence=f"Set-Cookie: {cookie_val}",
                        remediation="Set the HttpOnly flag on all session cookies.",
                        owasp_category="A07:2021-Identification and Authentication Failures"
                    ))
                if "Secure" not in cookie_val:
                     findings.append(VulnerabilityFinding(
                        name="Missing Secure Flag on Cookie",
                        description="Cookies can be sent over unencrypted connections.",
                        severity=Severity.MEDIUM,
                        url=target_url,
                        evidence=f"Set-Cookie: {cookie_val}",
                        remediation="Set the Secure flag on all session cookies (requires HTTPS).",
                        owasp_category="A07:2021-Identification and Authentication Failures"
                    ))
        except Exception:
            pass
            
        # Check for Common Auth Bypass / Default Creds (very basic)
        # This is risky/aggressive, so skipping default creds for "ethical" safety defaults (unless requested).
        # We will instead just check for open administrative pages that SHOULD use auth.

    return findings
