import httpx
from app.models.scan_models import VulnerabilityFinding, Severity

COMMON_PATHS = [
    ".env",
    "robots.txt",
    "admin",
    "login",
    "dashboard",
    "config.php",
    "backup",
    ".git"
]

async def scan_directory_enum(target_url: str) -> list[VulnerabilityFinding]:
    findings = []
    
    # Ensure URL ends with / if we are appending, or handle cleanly
    # Actually, we want to try target_url/path
    base_url = target_url.rstrip("/")
    
    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
        for path in COMMON_PATHS:
            url = f"{base_url}/{path}"
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    findings.append(VulnerabilityFinding(
                        name=f"Exposed File/Directory: {path}",
                        description=f"Found accessible resource at {path}",
                        severity=Severity.MEDIUM if path in [".env", ".git"] else Severity.LOW,
                        url=url,
                        evidence=f"Status Code: {response.status_code}",
                        remediation="Ensure sensitive files are not accessible or protected by authentication.",
                        owasp_category="A01:2021-Broken Access Control"
                    ))
                elif response.status_code == 403:
                     findings.append(VulnerabilityFinding(
                        name=f"Forbidden Resource Discovered: {path}",
                        description=f"Resource exists but is forbidden at {path}",
                        severity=Severity.INFO,
                        url=url,
                        evidence=f"Status Code: {response.status_code}",
                        remediation="Verify if this resource should be exposed.",
                        owasp_category="A01:2021-Broken Access Control"
                    ))
            except Exception:
                pass

    return findings
