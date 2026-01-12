import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from app.models.scan_models import VulnerabilityFinding, Severity

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\" onmouseover=\"alert('XSS')",
    "<img src=x onerror=alert('XSS')>"
]

async def scan_xss(target_url: str) -> list[VulnerabilityFinding]:
    findings = []
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return []

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        for param, values in params.items():
            for payload in XSS_PAYLOADS:
                new_params = params.copy()
                new_params[param] = [values[0] + payload] # Append or Replace? Usually replace is better for XSS testing, or append.
                # Let's try Replace explicitly to see if it reflects
                new_params[param] = [payload]
                
                query_string = urlencode(new_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    query_string,
                    parsed.fragment
                ))

                try:
                    response = await client.get(test_url)
                    content = response.text
                    
                    if payload in content:
                        findings.append(VulnerabilityFinding(
                            name="Reflected Cross-Site Scripting (XSS)",
                            description=f"The parameter '{param}' reflects input without proper sanitization.",
                            severity=Severity.MEDIUM,
                            url=test_url,
                            evidence=f"Payload found in response: {payload}",
                            remediation="Encode all user-supplied data before rendering it in the browser.",
                            owasp_category="A03:2021-Injection"
                        ))
                except Exception as e:
                     print(f"Error scanning XSS for {test_url}: {e}")

    return findings
