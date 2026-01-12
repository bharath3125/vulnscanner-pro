from pydantic import BaseModel
from typing import List, Optional
from enum import Enum
from datetime import datetime

class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    INFO = "Info"

class ScanType(str, Enum):
    FULL = "full"
    SQLI = "sqli"
    XSS = "xss"
    HEADERS = "headers"
    NMAP = "nmap"
    DIR_ENUM = "dir_enum"
    SENSITIVE_DATA = "sensitive_data"
    BROKEN_AUTH = "broken_auth"
    OUTDATED_COMPONENTS = "outdated_components"
    OWASP_TOP_10 = "owasp_top_10"

class ScanRequest(BaseModel):
    url: str
    scan_types: List[ScanType] = [ScanType.FULL]

class VulnerabilityFinding(BaseModel):
    name: str
    description: str
    severity: Severity
    url: str
    evidence: Optional[str] = None
    remediation: str
    owasp_category: Optional[str] = None

class ScanResult(BaseModel):
    target_url: str
    scan_id: str
    timestamp: datetime
    active_modules: List[str]
    findings: List[VulnerabilityFinding]
    summary: dict
