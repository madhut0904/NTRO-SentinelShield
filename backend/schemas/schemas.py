"""
NTRO SentinelShield - Pydantic Validation & Serialization Schemas
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# Safety & Target Schemas
class TargetBase(BaseModel):
    name: str = Field(..., example="World Monitor Sandbox")
    repo_path: Optional[str] = Field(None, example="./sandbox/worldmonitor")
    docker_compose_path: Optional[str] = Field(None, example="./sandbox/docker-compose.yml")
    branch: str = Field(default="main")
    environment: str = Field(default="SANDBOX")
    target_url: str = Field(..., example="http://localhost:8080")
    description: Optional[str] = None

class TargetCreate(TargetBase):
    pass

class TargetResponse(TargetBase):
    id: str
    is_approved_sandbox: bool
    safety_status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

# Evidence Schemas
class EvidenceResponse(BaseModel):
    id: str
    evidence_code: str
    finding_id: str
    timestamp: datetime
    test_identity: str
    request_data: Dict[str, Any]
    response_data: Dict[str, Any]
    source_file: Optional[str]
    code_line: Optional[int]
    log_snippet: Optional[str]
    sha256_hash: str

    class Config:
        from_attributes = True

# PoC Schemas
class PoCTestResponse(BaseModel):
    id: str
    finding_id: str
    title: str
    purpose: str
    target_url: str
    method: str
    test_identity: str
    headers: Dict[str, Any]
    payload: Dict[str, Any]
    expected_result: str
    actual_result: Optional[str]
    status: str
    is_safe: bool
    executed_at: Optional[datetime]

    class Config:
        from_attributes = True

class PoCExecuteRequest(BaseModel):
    finding_id: str

# Remediation Schemas
class RemediationResponse(BaseModel):
    id: str
    finding_id: str
    problem: str
    root_cause: str
    recommended_fix: str
    safe_patch_diff: str
    security_impact: str
    applied_to_sandbox: bool
    applied_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

class RemediationApplyRequest(BaseModel):
    finding_id: str

# Retest Schemas
class RetestResponse(BaseModel):
    id: str
    finding_id: str
    before_status_code: int
    before_response: Optional[str]
    after_status_code: int
    after_response: Optional[str]
    result: str
    verified_status: str
    retest_timestamp: datetime
    execution_notes: Optional[str]

    class Config:
        from_attributes = True

class RetestExecuteRequest(BaseModel):
    finding_id: str

# Finding Schemas
class FindingResponse(BaseModel):
    id: str
    finding_code: str
    assessment_id: str
    title: str
    category: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str]
    cwe: str
    file_path: Optional[str]
    line_number: Optional[int]
    code_snippet: Optional[str]
    description: str
    status: str
    confidence: str
    is_correlated: bool
    static_evidence: Dict[str, Any]
    runtime_evidence: Dict[str, Any]
    api_evidence: Dict[str, Any]
    auth_context: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    evidences: Optional[List[EvidenceResponse]] = []
    poc: Optional[PoCTestResponse] = None
    remediation: Optional[RemediationResponse] = None
    retests: Optional[List[RetestResponse]] = []

    class Config:
        from_attributes = True

# Security Control Schemas
class SecurityControlResponse(BaseModel):
    id: str
    assessment_id: str
    control_id: str
    name: str
    category: str
    expected: str
    tested: bool
    result: str
    evidence_id: Optional[str]
    confidence: str
    description: Optional[str]

    class Config:
        from_attributes = True

# Endpoint Schemas
class EndpointResponse(BaseModel):
    id: str
    assessment_id: str
    method: str
    path: str
    auth_required: bool
    auth_mechanism: str
    parameters: List[Any]
    sensitive_fields: List[Any]
    risk_level: str
    discovered_via: str

    class Config:
        from_attributes = True

# Dependency & Secret Schemas
class DependencyResponse(BaseModel):
    id: str
    package_name: str
    current_version: str
    fixed_version: Optional[str]
    cve: str
    severity: str
    manifest_file: str
    description: Optional[str]

    class Config:
        from_attributes = True

class SecretFindingResponse(BaseModel):
    id: str
    file_path: str
    line_number: int
    secret_type: str
    masked_value: str
    entropy_score: float
    sha256_hash: str

    class Config:
        from_attributes = True

# Scan Job Schemas
class ScanJobResponse(BaseModel):
    id: str
    assessment_id: str
    job_type: str
    status: str
    progress_pct: int
    findings_count: int
    log_output: str
    started_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True

# Assessment Schemas
class AssessmentCreate(BaseModel):
    target_id: str
    title: str = Field(..., example="World Monitor Security Audit 2026")
    summary: Optional[str] = None

class AssessmentResponse(BaseModel):
    id: str
    target_id: str
    title: str
    status: str
    assurance_score: float
    score_breakdown: Dict[str, Any]
    summary: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
    target: Optional[TargetResponse] = None
    scan_jobs: Optional[List[ScanJobResponse]] = []
    findings: Optional[List[FindingResponse]] = []
    controls: Optional[List[SecurityControlResponse]] = []

    class Config:
        from_attributes = True

# Report Schemas
class ReportGenerateRequest(BaseModel):
    assessment_id: str
    report_type: str = Field(default="PDF", example="PDF")  # PDF, HTML, JSON

class ReportResponse(BaseModel):
    id: str
    assessment_id: str
    report_type: str
    title: str
    file_path: Optional[str]
    content_summary: Optional[str]
    generated_at: datetime

    class Config:
        from_attributes = True

# Audit Log Schema
class AuditLogResponse(BaseModel):
    id: str
    user: str
    action: str
    target: Optional[str]
    assessment_id: Optional[str]
    timestamp: datetime
    result: str
    details: Dict[str, Any]

    class Config:
        from_attributes = True

# Dashboard Stats Schema
class DashboardStatsResponse(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    validated_findings: int
    false_positives: int
    fixed_findings: int
    regression_findings: int
    security_controls_tested: int
    tests_passed: int
    tests_failed: int
    assurance_score: float
    score_breakdown: Dict[str, float]
    category_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    posture_trend: List[Dict[str, Any]]
