import httpx
import re
from app.models.scan_models import VulnerabilityFinding, Severity

# Regex patterns for sensitive data
PATTERNS = {
    "Email Address": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Private Key": r"-----BEGIN PRIVATE KEY-----",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Social Security Number (US)": r"\b\d{3}-\d{2}-\d{4}\b"
}

async def scan_sensitive_data(target_url: str) -> list[VulnerabilityFinding]:
    findings = []
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            response = await client.get(target_url)
            content = response.text

            for name, pattern in PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    # Limit evidence length
                    evidence = str(matches[:3]) 
                    findings.append(VulnerabilityFinding(
                        name=f"Sensitive Data Exposure: {name}",
                        description=f"Found potential {name} in the response body.",
                        severity=Severity.HIGH,
                        url=target_url,
                        evidence=evidence,
                        remediation="Ensure sensitive data is not hardcoded or leaked in client-side code.",
                        owasp_category="A04:2021-Insecure Design (Sensitive Data Exposure)"
                    ))

    except Exception as e:
        print(f"Error scanning sensitive data for {target_url}: {e}")

    return findings
