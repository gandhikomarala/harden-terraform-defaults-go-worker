from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Finding(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: SeverityLevel
    resource_id: str
    resource_type: str
    provider: str
    file_name: str
    line_start: int
    line_end: int
    standard_mappings: Dict[str, str]
    risk: str
    evidence: str
    remediation: str
    status: str = "OPEN"

class ScanSummary(BaseModel):
    total_resources: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration_ms: float

class ScanRequest(BaseModel):
    configuration: str
    format: str = "terraform" # terraform, cloudformation, yaml, json
    filename: str = "main.tf"

class ScanResponse(BaseModel):
    scan_id: str
    filename: str
    format: str
    summary: ScanSummary
    findings: List[Finding]

class RemediationRequest(BaseModel):
    finding_id: str
    configuration: str
    format: str = "terraform"

class RemediationResponse(BaseModel):
    finding_id: str
    vulnerable_code: str
    secure_code: str
    unified_diff: str
    explanation: str
