"""
NTRO SentinelShield - SQLAlchemy ORM Models
Defines all database entities for security assessment, correlation, evidence vault, and assurance tracking.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, Integer, Float, Boolean, DateTime, ForeignKey, Enum as SQLEnum, JSON
)
from sqlalchemy.orm import relationship
from backend.database.db import Base

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    role = Column(String(32), default="SECURITY_ANALYST")  # ADMIN, SECURITY_ANALYST, VIEWER
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)


class Target(Base):
    __tablename__ = "targets"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(128), nullable=False)
    repo_path = Column(String(512), nullable=True)
    docker_compose_path = Column(String(512), nullable=True)
    branch = Column(String(64), default="main")
    environment = Column(String(32), default="SANDBOX")  # SANDBOX, LOCAL, PRODUCTION_BLOCKED
    target_url = Column(String(256), nullable=False)
    is_approved_sandbox = Column(Boolean, default=True)
    safety_status = Column(String(16), default="GREEN")  # GREEN (Sandbox/Local), RED (Production/Blocked)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    
    assessments = relationship("Assessment", back_populates="target", cascade="all, delete-orphan")


class Assessment(Base):
    __tablename__ = "assessments"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    title = Column(String(256), nullable=False)
    status = Column(String(32), default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED
    assurance_score = Column(Float, default=0.0)
    score_breakdown = Column(JSON, default=dict)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)
    
    target = relationship("Target", back_populates="assessments")
    scan_jobs = relationship("ScanJob", back_populates="assessment", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")
    controls = relationship("SecurityControl", back_populates="assessment", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="assessment", cascade="all, delete-orphan")
    dependencies = relationship("DependencyItem", back_populates="assessment", cascade="all, delete-orphan")
    secrets = relationship("SecretFinding", back_populates="assessment", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="assessment", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    assessment_id = Column(String, ForeignKey("assessments.id"), nullable=False)
    job_type = Column(String(64), nullable=False)  # REPO_DISCOVERY, SAST, API_SECURITY, DEPENDENCY, AUTH_TEST, DAST, CORRELATION
    status = Column(String(32), default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED
    progress_pct = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    log_output = Column(Text, default="")
    started_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)
    
    assessment = relationship("Assessment", back_populates="scan_jobs")


class Endpoint(Base):
    __tablename__ = "endpoints"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    assessment_id = Column(String, ForeignKey("assessments.id"), nullable=False)
    method = Column(String(16), nullable=False)
    path = Column(String(256), nullable=False)
    auth_required = Column(Boolean, default=False)
    auth_mechanism = Column(String(64), default="None")
    parameters = Column(JSON, default=list)
    sensitive_fields = Column(JSON, default=list)
    risk_level = Column(String(32), default="LOW")
    discovered_via = Column(String(64), default="SAST_ROUTING")
    
    assessment = relationship("Assessment", back_populates="endpoints")


class SecurityControl(Base):
    __tablename__ = "security_controls"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    assessment_id = Column(String, ForeignKey("assessments.id"), nullable=False)
    control_id = Column(String(64), nullable=False)  # e.g., CTRL-AUTH-01
    name = Column(String(128), nullable=False)
    category = Column(String(64), nullable=False)  # Authentication, Authorization, Input Validation, CORS, Rate Limiting, etc.
    expected = Column(String(128), nullable=False)
    tested = Column(Boolean, default=False)
    result = Column(String(32), default="NOT_TESTED")  # PASS, FAIL, WARN, NOT_TESTED
    evidence_id = Column(String(64), nullable=True)
    confidence = Column(String(32), default="HIGH")
    description = Column(Text, nullable=True)
    
    assessment = relationship("Assessment", back_populates="controls")


class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    finding_code = Column(String(32), unique=True, index=True, nullable=False)  # e.g. SS-001
    assessment_id = Column(String, ForeignKey("assessments.id"), nullable=False)
    title = Column(String(256), nullable=False)
    category = Column(String(64), nullable=False)  # Broken Authorization, Injection, Secrets, Dependencies, etc.
    severity = Column(String(32), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(128), nullable=True)
    cwe = Column(String(64), default="CWE-200")
    file_path = Column(String(512), nullable=True)
    line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    description = Column(Text, nullable=False)
    status = Column(String(32), default="OPEN")  # OPEN, VALIDATED, FIXED, REGRESSION, FALSE_POSITIVE
    confidence = Column(String(32), default="MEDIUM")  # LOW, MEDIUM, HIGH, VALIDATED
    
    # Cross-Layer Correlation Data
    static_evidence = Column(JSON, default=dict)
    runtime_evidence = Column(JSON, default=dict)
    api_evidence = Column(JSON, default=dict)
    auth_context = Column(JSON, default=dict)
    is_correlated = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
    
    assessment = relationship("Assessment", back_populates="findings")
    evidences = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")
    poc = relationship("PoCTest", back_populates="finding", uselist=False, cascade="all, delete-orphan")
    remediation = relationship("Remediation", back_populates="finding", uselist=False, cascade="all, delete-orphan")
    retests = relationship("Retest", back_populates="finding", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    evidence_code = Column(String(32), unique=True, index=True, nullable=False)  # e.g. EV-1001
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    timestamp = Column(DateTime, default=utc_now)
    test_identity = Column(String(64), default="ANONYMOUS")  # ADMIN, USER_A, USER_B, ANONYMOUS
    request_data = Column(JSON, default=dict)
    response_data = Column(JSON, default=dict)
    source_file = Column(String(512), nullable=True)
    code_line = Column(Integer, nullable=True)
    log_snippet = Column(Text, nullable=True)
    sha256_hash = Column(String(64), nullable=False)
    
    finding = relationship("Finding", back_populates="evidences")


class PoCTest(Base):
    __tablename__ = "poc_tests"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    title = Column(String(256), nullable=False)
    purpose = Column(Text, nullable=False)
    target_url = Column(String(256), nullable=False)
    method = Column(String(16), default="GET")
    test_identity = Column(String(64), default="USER_B")
    headers = Column(JSON, default=dict)
    payload = Column(JSON, default=dict)
    expected_result = Column(Text, nullable=False)
    actual_result = Column(Text, nullable=True)
    status = Column(String(32), default="READY")  # READY, PROVEN, FAILED
    is_safe = Column(Boolean, default=True)  # True = Non-destructive
    executed_at = Column(DateTime, nullable=True)
    
    finding = relationship("Finding", back_populates="poc")


class Remediation(Base):
    __tablename__ = "remediations"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    problem = Column(Text, nullable=False)
    root_cause = Column(Text, nullable=False)
    recommended_fix = Column(Text, nullable=False)
    safe_patch_diff = Column(Text, nullable=False)
    security_impact = Column(Text, nullable=False)
    applied_to_sandbox = Column(Boolean, default=False)
    applied_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    
    finding = relationship("Finding", back_populates="remediation")


class Retest(Base):
    __tablename__ = "retests"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    before_status_code = Column(Integer, nullable=False)
    before_response = Column(Text, nullable=True)
    after_status_code = Column(Integer, nullable=False)
    after_response = Column(Text, nullable=True)
    result = Column(String(32), default="FIXED")  # FIXED, STILL_VULNERABLE, REGRESSION
    verified_status = Column(String(64), default="SECURITY CONTROL VERIFIED")
    retest_timestamp = Column(DateTime, default=utc_now)
    execution_notes = Column(Text, nullable=True)
    
    finding = relationship("Finding", back_populates="retests")


class DependencyItem(Base):
    __tablename__ = "dependencies"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    assessment_id = Column(String, ForeignKey("assessments.id"), nullable=False)
    package_name = Column(String(128), nullable=False)
    current_version = Column(String(64), nullable=False)
    fixed_version = Column(String(64), nullable=True)
    cve = Column(String(64), nullable=False)
    severity = Column(String(32), default="HIGH")
    manifest_file = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    
    assessment = relationship("Assessment", back_populates="dependencies")


class SecretFinding(Base):
    __tablename__ = "secrets"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    assessment_id = Column(String, ForeignKey("assessments.id"), nullable=False)
    file_path = Column(String(512), nullable=False)
    line_number = Column(Integer, nullable=False)
    secret_type = Column(String(64), nullable=False)
    masked_value = Column(String(128), nullable=False)  # sk_live_********
    entropy_score = Column(Float, default=0.0)
    sha256_hash = Column(String(64), nullable=False)
    
    assessment = relationship("Assessment", back_populates="secrets")


class Report(Base):
    __tablename__ = "reports"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    assessment_id = Column(String, ForeignKey("assessments.id"), nullable=False)
    report_type = Column(String(16), default="PDF")  # PDF, HTML, JSON
    title = Column(String(256), nullable=False)
    file_path = Column(String(512), nullable=True)
    content_summary = Column(Text, nullable=True)
    generated_at = Column(DateTime, default=utc_now)
    
    assessment = relationship("Assessment", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    user = Column(String(64), default="system")
    action = Column(String(128), nullable=False)
    target = Column(String(128), nullable=True)
    assessment_id = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=utc_now)
    result = Column(String(32), default="SUCCESS")
    details = Column(JSON, default=dict)
