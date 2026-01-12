import httpx
from app.models.scan_models import VulnerabilityFinding, Severity

REQUIRED_HEADERS = {
    "Strict-Transport-Security": "Protects against man-in-the-middle attacks.",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks.",
    "X-Content-Type-Options": "Prevents MIME-sniffing.",
    "X-Frame-Options": "Prevents Clickjacking.",
    "X-XSS-Protection": "Legacy XSS protection (though CSP is preferred)."
}

async def scan_headers(url: str) -> list[VulnerabilityFinding]:
    findings = []
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            response = await client.get(url)
            headers = response.headers

            for header, desc in REQUIRED_HEADERS.items():
                if header not in headers:
                    findings.append(VulnerabilityFinding(
                        name=f"Missing Security Header: {header}",
                        description=f"The {header} header is missing. {desc}",
                        severity=Severity.LOW,
                        url=url,
                        evidence="Header not found in response.",
                        remediation=f"Configure the server to send the {header} header.",
                        owasp_category="A05:2021-Security Misconfiguration"
                    ))
    except Exception as e:
        print(f"Error scanning headers for {url}: {e}")
        # Ideally we return an error finding or just log it
    
    return findings
