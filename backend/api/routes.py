"""
NTRO SentinelShield - FastAPI REST API Router
"""
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from typing import List, Optional, Dict, Any
import os

from backend.database.repo import (
    TargetRepo, AssessmentRepo, FindingRepo, ControlRepo, EndpointRepo,
    EvidenceRepo, PoCRepo, RemediationRepo, RetestRepo, ReportRepo, AuditRepo
)
from backend.utils.safety import validate_target_safety
from backend.services.orchestrator import ScanOrchestrator
from backend.services.report_service import ReportService
from backend.engines.poc.poc_engine import SafePoCEngine
from backend.engines.remediation.remediation_engine import RemediationEngine
from backend.engines.retest.retest_engine import RetestEngine

router = APIRouter(prefix="/api")

# ==================== TARGETS ====================
@router.post("/targets")
def create_target(target_in: Dict[str, Any]):
    safety = validate_target_safety(target_in.get("target_url", ""))
    if not safety["is_safe"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target rejected by SentinelShield Safety Policy: {safety['reason']}"
        )
    return TargetRepo.create({
        "name": target_in["name"],
        "repo_path": target_in.get("repo_path"),
        "docker_compose_path": target_in.get("docker_compose_path"),
        "branch": target_in.get("branch", "main"),
        "environment": target_in.get("environment", "SANDBOX"),
        "target_url": target_in["target_url"],
        "is_approved_sandbox": 1,
        "safety_status": safety["safety_status"],
        "description": target_in.get("description")
    })

@router.get("/targets")
def get_targets():
    return TargetRepo.list_all()

# ==================== ASSESSMENTS ====================
@router.post("/assessments")
async def create_assessment(assessment_in: Dict[str, Any]):
    target = TargetRepo.get(assessment_in["target_id"])
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    safety = validate_target_safety(target["target_url"])
    if not safety["is_safe"]:
        raise HTTPException(status_code=400, detail=f"Cannot assess unapproved target: {safety['reason']}")

    assessment = AssessmentRepo.create({
        "target_id": target["id"],
        "title": assessment_in["title"],
        "status": "PENDING",
        "summary": assessment_in.get("summary") or "Initiating 15-stage continuous assurance security audit..."
    })

    orchestrator = ScanOrchestrator()
    completed_assessment = await orchestrator.execute_full_assessment(assessment["id"])
    return completed_assessment

@router.get("/assessments")
def get_assessments():
    return AssessmentRepo.list_all()

@router.get("/assessments/{assessment_id}")
def get_assessment_detail(assessment_id: str):
    assessment = AssessmentRepo.get(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment

# ==================== FINDINGS ====================
@router.get("/findings")
def get_findings(assessment_id: Optional[str] = None, severity: Optional[str] = None):
    return FindingRepo.list_all(assessment_id=assessment_id, severity=severity)

@router.get("/findings/{finding_id}")
def get_finding_detail(finding_id: str):
    finding = FindingRepo.get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

# ==================== SAFE POC RUNNER ====================
@router.post("/poc/execute")
async def execute_poc(poc_req: Dict[str, Any]):
    finding_id = poc_req.get("finding_id")
    finding = FindingRepo.get(finding_id)
    if not finding or not finding.get("poc"):
        raise HTTPException(status_code=404, detail="PoC test definition not found for finding")
        
    target_url = finding["poc"]["target_url"]
    poc_engine = SafePoCEngine(target_url)
    result = await poc_engine.execute_poc(finding["poc"])
    
    PoCRepo.update_result(finding["id"], result.get("status", "PROVEN"), result.get("actual_result", ""))
    return {
        "success": True,
        "poc_id": finding["poc"]["id"],
        "status": result.get("status", "PROVEN"),
        "result": result
    }

# ==================== REMEDIATION & RETEST ====================
@router.post("/remediation/{finding_id}/apply")
def apply_remediation(finding_id: str):
    finding = FindingRepo.get(finding_id)
    if not finding or not finding.get("remediation"):
        raise HTTPException(status_code=404, detail="Remediation not found")
        
    rem_engine = RemediationEngine("http://localhost:8080")
    apply_res = rem_engine.apply_patch_to_sandbox(finding["finding_code"], finding["remediation"]["safe_patch_diff"])
    
    RemediationRepo.mark_applied(finding["id"])
    FindingRepo.update_status(finding["id"], "FIXED")
    return apply_res

@router.post("/retest/{finding_id}")
async def execute_retest(finding_id: str):
    finding = FindingRepo.get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    is_patched = finding["remediation"]["applied_to_sandbox"] if finding.get("remediation") else True
    retest_engine = RetestEngine("http://localhost:8080")
    retest_data = await retest_engine.execute_retest({
        "id": finding["id"],
        "finding_code": finding["finding_code"],
        "category": finding["category"]
    }, is_patched=is_patched)
    
    RetestRepo.create({
        "finding_id": finding["id"],
        "before_status_code": retest_data["before_status_code"],
        "before_response": retest_data["before_response"],
        "after_status_code": retest_data["after_status_code"],
        "after_response": retest_data["after_response"],
        "result": retest_data["result"],
        "verified_status": retest_data["verified_status"],
        "execution_notes": retest_data["execution_notes"]
    })
    
    FindingRepo.update_status(finding["id"], "FIXED" if retest_data["result"] == "FIXED" else "STILL_VULNERABLE")
    return retest_data

# ==================== SECURITY CONTROLS ====================
@router.get("/security-controls")
def get_security_controls(assessment_id: Optional[str] = None):
    return ControlRepo.list_by_assessment(assessment_id)

# ==================== ATTACK SURFACE ====================
@router.get("/attack-surface/{assessment_id}")
def get_attack_surface(assessment_id: str):
    endpoints = EndpointRepo.list_by_assessment(assessment_id)
    findings = FindingRepo.list_all(assessment_id=assessment_id)

    nodes = [
        {"id": "frontend", "label": "Web Frontend (Next.js / UI)", "type": "layer", "risk": "LOW", "count": 1},
        {"id": "api_gateway", "label": "API Gateway & Router", "type": "layer", "risk": "MEDIUM", "count": len(endpoints)},
        {"id": "auth_service", "label": "Authentication & RBAC", "type": "control", "risk": "HIGH", "count": 1},
        {"id": "dossier_service", "label": "Intel Dossiers API", "type": "endpoint", "risk": "CRITICAL", "count": 1},
        {"id": "database", "label": "Database & State Store", "type": "storage", "risk": "LOW", "count": 1}
    ]
    edges = [
        {"from": "frontend", "to": "api_gateway", "relation": "HTTPS / JSON"},
        {"from": "api_gateway", "to": "auth_service", "relation": "JWT Verification"},
        {"from": "api_gateway", "to": "dossier_service", "relation": "Route Delegation"},
        {"from": "dossier_service", "to": "database", "relation": "Query Execution"}
    ]

    return {
        "assessment_id": assessment_id,
        "nodes": nodes,
        "edges": edges,
        "endpoints": endpoints,
        "findings_summary": {
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW")
        }
    }

# ==================== REPORTS ====================
@router.post("/reports/generate")
def generate_report(req: Dict[str, Any]):
    assessment_id = req.get("assessment_id")
    report_type = req.get("report_type", "PDF").upper()
    assessment = AssessmentRepo.get(assessment_id)
    if not assessment:
        assessments = AssessmentRepo.list_all()
        assessment = assessments[0] if assessments else None
        
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
        
    report_service = ReportService()
    if report_type == "PDF":
        file_path = report_service.generate_pdf_report(assessment)
    elif report_type == "HTML":
        file_path = report_service.generate_html_report(assessment)
    else:
        file_path = report_service.generate_json_report(assessment)

    return ReportRepo.create({
        "assessment_id": assessment["id"],
        "report_type": report_type,
        "title": f"Security Assurance Report - {assessment['title']}",
        "file_path": file_path,
        "content_summary": f"Automated {report_type} report containing {len(assessment.get('findings', []))} validated findings."
    })

@router.get("/reports/download/{filename}")
def download_report_file(filename: str):
    file_path = os.path.join("./reports", filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(file_path)

# ==================== DASHBOARD STATS ====================
@router.get("/dashboard")
def get_dashboard_metrics():
    findings = FindingRepo.list_all()
    controls = ControlRepo.list_by_assessment()
    assessments = AssessmentRepo.list_all()
    latest_assessment = assessments[0] if assessments else None

    total_findings = len(findings)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    validated = sum(1 for f in findings if f.get("confidence") == "VALIDATED")
    fixed = sum(1 for f in findings if f.get("status") == "FIXED")

    tested_controls = sum(1 for c in controls if c.get("tested"))
    passed_controls = sum(1 for c in controls if c.get("result") == "PASS")
    failed_controls = sum(1 for c in controls if c.get("result") in ["FAIL", "WARN"])

    score = latest_assessment.get("assurance_score", 0.0) if latest_assessment else 0.0
    breakdown = latest_assessment.get("score_breakdown") if (latest_assessment and latest_assessment.get("score_breakdown")) else {
        "Authentication": 0.0,
        "Authorization": 0.0,
        "API Security": 0.0,
        "Input Validation": 0.0,
        "Dependencies": 0.0,
        "Configuration": 0.0,
        "Security Headers": 0.0,
        "Secrets": 0.0
    }

    category_dist = {}
    for f in findings:
        cat = f.get("category", "General")
        category_dist[cat] = category_dist.get(cat, 0) + 1

    severity_dist = {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low}

    posture_trend = [
        {"scan": ass.get("title", f"Audit {idx+1}")[:12], "score": int(ass.get("assurance_score", 0.0)), "findings": len(FindingRepo.list_all(assessment_id=ass["id"]))}
        for idx, ass in enumerate(reversed(assessments[:5]))
    ] if assessments else []

    return {
        "total_findings": total_findings,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "validated_findings": validated,
        "false_positives": 0,
        "fixed_findings": fixed,
        "regression_findings": 0,
        "security_controls_tested": tested_controls,
        "tests_passed": passed_controls,
        "tests_failed": failed_controls,
        "assurance_score": score,
        "score_breakdown": breakdown,
        "category_distribution": category_dist,
        "severity_distribution": severity_dist,
        "posture_trend": posture_trend
    }
