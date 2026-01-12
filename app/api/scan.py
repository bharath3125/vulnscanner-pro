from fastapi import APIRouter, BackgroundTasks, HTTPException
from typing import Dict
import uuid
import asyncio
from datetime import datetime

from app.models.scan_models import ScanRequest, ScanResult, ScanType, VulnerabilityFinding
from app.scanner.sqli import scan_sqli
from app.scanner.xss import scan_xss
from app.scanner.headers import scan_headers
from app.scanner.nmap_scan import scan_nmap
from app.scanner.directory_enum import scan_directory_enum
from app.scanner.sensitive_data import scan_sensitive_data
from app.scanner.broken_auth import scan_broken_auth
from app.scanner.outdated_components import scan_outdated_components

router = APIRouter()

# In-memory storage for scan results (Use database in production)
scan_results: Dict[str, ScanResult] = {}
scan_status: Dict[str, str] = {} # "running", "completed", "failed"

async def run_scan(scan_id: str, request: ScanRequest):
    findings = []
    active_modules = []
    
    url = request.url
    
    # Quick fix for URLs without scheme
    if not url.startswith("http"):
        url = "http://" + url

    try:
        tasks = []
        
        # Determine modules to run
        run_all = ScanType.FULL in request.scan_types
        run_owasp = ScanType.OWASP_TOP_10 in request.scan_types
        
        if run_all or run_owasp or ScanType.HEADERS in request.scan_types:
            tasks.append(scan_headers(url))
            active_modules.append("headers")
            
        if run_all or run_owasp or ScanType.SQLI in request.scan_types:
            tasks.append(scan_sqli(url))
            active_modules.append("sqli")
            
        if run_all or run_owasp or ScanType.XSS in request.scan_types:
            tasks.append(scan_xss(url))
            active_modules.append("xss")
            
        if run_all or run_owasp or ScanType.DIR_ENUM in request.scan_types:
            tasks.append(scan_directory_enum(url))
            active_modules.append("dir_enum")
            
        if run_all or run_owasp or ScanType.NMAP in request.scan_types:
            tasks.append(scan_nmap(url))
            active_modules.append("nmap")
            
        if run_all or run_owasp or ScanType.SENSITIVE_DATA in request.scan_types:
             tasks.append(scan_sensitive_data(url))
             active_modules.append("sensitive_data")
             
        if run_all or run_owasp or ScanType.BROKEN_AUTH in request.scan_types:
            tasks.append(scan_broken_auth(url))
            active_modules.append("broken_auth")
            
        if run_all or run_owasp or ScanType.OUTDATED_COMPONENTS in request.scan_types:
            tasks.append(scan_outdated_components(url))
            active_modules.append("outdated_components")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if isinstance(res, list): # List of findings
                findings.extend(res)
            elif isinstance(res, Exception):
                print(f"Module error: {res}")

        # Summary
        summary = {
            "Critical": len([f for f in findings if f.severity == "Critical"]),
            "High": len([f for f in findings if f.severity == "High"]),
            "Medium": len([f for f in findings if f.severity == "Medium"]),
            "Low": len([f for f in findings if f.severity == "Low"]),
            "Info": len([f for f in findings if f.severity == "Info"])
        }

        scan_results[scan_id] = ScanResult(
            target_url=url,
            scan_id=scan_id,
            timestamp=datetime.now(),
            active_modules=active_modules,
            findings=findings,
            summary=summary
        )
        scan_status[scan_id] = "completed"

    except Exception as e:
        print(f"Scan failed: {e}")
        scan_status[scan_id] = "failed"

@router.post("/scan", response_model=Dict[str, str])
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = "running"
    background_tasks.add_task(run_scan, scan_id, request)
    return {"scan_id": scan_id, "status": "started"}

@router.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    if scan_id not in scan_status:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    
    status = scan_status[scan_id]
    if status == "running":
        return {"status": "running"}
    elif status == "failed":
        return {"status": "failed"}
    
    result = scan_results.get(scan_id)
    return {"status": "completed", "result": result}
