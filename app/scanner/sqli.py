import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from app.models.scan_models import VulnerabilityFinding, Severity

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "microsoft ole db provider for odbc drivers error",
    "sqlstate[",
    "syntax error"
]

async def scan_sqli(target_url: str) -> list[VulnerabilityFinding]:
    findings = []
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        # If no params in URL, we could look for forms, but for this module scope 
        # let's assume we scan the provided URL params.
        return []

    test_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        for param, values in params.items():
            for payload in test_payloads:
                # Construct new URL with payload
                # Note: We only test the first value of the param for simplicity
                new_params = params.copy()
                new_params[param] = [values[0] + payload]
                query_string = urlencode(new_params, doseq=True)
                
                # Reconstruct URL
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
                    content = response.text.lower()
                    
                    for error in SQL_ERRORS:
                        if error in content:
                            findings.append(VulnerabilityFinding(
                                name="SQL Injection (Error-based)",
                                description=f"The parameter '{param}' appears to be vulnerable to SQL Injection.",
                                severity=Severity.HIGH,
                                url=test_url,
                                evidence=f"Database error found in response: {error}",
                                remediation="Use prepared statements or parameterized queries.",
                                owasp_category="A03:2021-Injection"
                            ))
                            break # Found one error for this param/payload, move to next
                    
                    # Optimization: If we found a vuln for this param, maybe stop testing other payloads for this param?
                    # For a thorough scan, we might want to continue, but for MVP let's break to avoid duplicates if multiple payloads trigger it.
                    # Actually, let's keep it simple.
                    
                except Exception as e:
                    print(f"Error scanning SQLi for {test_url}: {e}")
    
    # Deduplicate findings based on param?
    # For now, return all distinct findings.
    return findings
