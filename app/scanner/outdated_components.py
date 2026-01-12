import httpx
import re
from app.models.scan_models import VulnerabilityFinding, Severity

# Simple signatures for outdated components
# In a real scanner, this would verify against a CVE database
SIGNATURES = [
    {
        "name": "jQuery",
        "pattern": r"jquery[.-](\d+\.\d+\.\d+)",
        "safe_version": "3.5.0", # Minimum safe version (simplified)
        "description": "Outdated jQuery version detected. Older versions may be vulnerable to XSS."
    },
    {
        "name": "Bootstrap",
        "pattern": r"bootstrap[.-](\d+\.\d+\.\d+)",
        "safe_version": "4.6.0", 
        "description": "Outdated Bootstrap version detected."
    },
    {
        "name": "AngularJS",
        "pattern": r"angular[.-](\d+\.\d+\.\d+)",
        "safe_version": "1.8.0",
        "description": "Outdated AngularJS version detected."
    }
]

async def scan_outdated_components(target_url: str) -> list[VulnerabilityFinding]:
    findings = []
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            response = await client.get(target_url)
            headers = response.headers
            content = response.text.lower()
            
            # 1. Check Headers (Server, X-Powered-By)
            if "server" in headers:
                server = headers["server"]
                # Heuristic: if server reveals version, it's info disclosure + potential outdated comp
                if any(char.isdigit() for char in server):
                     findings.append(VulnerabilityFinding(
                        name=f"Server Header Version Disclosure: {server}",
                        description=f"The server header reveals version information: {server}",
                        severity=Severity.LOW,
                        url=target_url,
                        evidence=f"Server: {server}",
                        remediation="Configure the server to hide version information.",
                        owasp_category="A06:2021-Vulnerable and Outdated Components"
                    ))

            if "x-powered-by" in headers:
                powered = headers["x-powered-by"]
                findings.append(VulnerabilityFinding(
                    name=f"Technology Disclosure: {powered}",
                    description=f"The X-Powered-By header reveals technology: {powered}",
                    severity=Severity.LOW,
                    url=target_url,
                    evidence=f"X-Powered-By: {powered}",
                    remediation="Remove the X-Powered-By header.",
                    owasp_category="A06:2021-Vulnerable and Outdated Components"
                ))

            # 2. Check HTML content for library signatures
            for sig in SIGNATURES:
                matches = re.search(sig["pattern"], content)
                if matches:
                    version = matches.group(1)
                    # Very simple string comparison - brittle but works for clear major versions
                    if version < sig["safe_version"]:
                         findings.append(VulnerabilityFinding(
                            name=f"Outdated Component: {sig['name']} {version}",
                            description=sig['description'],
                            severity=Severity.MEDIUM,
                            url=target_url,
                            evidence=f"Found signature matching version {version}",
                            remediation=f"Upgrade {sig['name']} to the latest stable version.",
                            owasp_category="A06:2021-Vulnerable and Outdated Components"
                        ))

    except Exception as e:
        print(f"Error scanning outdated components for {target_url}: {e}")

    return findings
