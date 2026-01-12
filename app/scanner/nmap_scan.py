import nmap
from urllib.parse import urlparse
from app.models.scan_models import VulnerabilityFinding, Severity
import shutil

async def scan_nmap(target_url: str) -> list[VulnerabilityFinding]:
    findings = []
    
    # Check if nmap is installed
    if not shutil.which("nmap"):
        findings.append(VulnerabilityFinding(
            name="Nmap Not Found",
            description="Nmap binary not found in system PATH. Port scanning skipped.",
            severity=Severity.INFO,
            url=target_url,
            evidence="N/A",
            remediation="Install Nmap on the server hosting this scanner.",
        ))
        return findings

    hostname = urlparse(target_url).hostname
    if not hostname:
         return []

    try:
        nm = nmap.PortScanner()
        # Simple scan: Top 100 ports, service version detection (-sV -F is fast)
        # Scan might block the thread. In async function, this is not ideal.
        # But for simplicity, we run it. For production, run in run_in_executor.
        
        # We'll use -F for Fast scan (100 ports)
        nm.scan(hostname, arguments='-F') 
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    if state == 'open':
                         findings.append(VulnerabilityFinding(
                            name=f"Open Port: {port}/{proto} ({service})",
                            description=f"Port {port} is open running {service}.",
                            severity=Severity.INFO, # Open port itself isn't a vuln, but good to know
                            url=target_url, 
                            evidence=f"State: {state}, Service: {service}",
                            remediation="Ensure only necessary ports are open.",
                            owasp_category="A05:2021-Security Misconfiguration"
                        ))
    except Exception as e:
        findings.append(VulnerabilityFinding(
            name="Nmap Scan Failed",
            description=f"Error running nmap: {str(e)}",
            severity=Severity.INFO,
            url=target_url,
            evidence=str(e),
            remediation="Check scanner logs.",
        ))

    return findings
