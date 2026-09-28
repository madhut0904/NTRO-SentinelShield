"""
Unit and Integration Tests for NTRO SentinelShield
"""
import pytest
import os
import sys

# Ensure backend package is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.utils.safety import validate_target_safety
from backend.utils.hasher import compute_sha256, mask_secret
from backend.utils.cvss import calculate_cvss_v31
from backend.engines.sast.sast_engine import SASTEngine
from backend.engines.api_security.api_engine import APISecurityEngine
from backend.engines.auth_engine.auth_tester import AuthEngine
from backend.engines.correlation.correlation_engine import CorrelationEngine
from backend.engines.retest.retest_engine import RetestEngine
from backend.engines.dependencies.dependency_scanner import DependencyScanner
from backend.engines.secrets.secret_scanner import SecretScanner
from backend.engines.poc.poc_engine import SafePoCEngine
from backend.engines.remediation.remediation_engine import RemediationEngine
from backend.services.report_service import ReportService

# 1. Target Safety Policy Tests
def test_safety_guardrails_blocks_production():
    result_prod = validate_target_safety("https://worldmonitor.app")
    assert result_prod["is_safe"] is False
    assert result_prod["safety_status"] == "RED"
    assert "strictly forbidden" in result_prod["reason"].lower() or "violation" in result_prod["reason"].lower()

    result_subdomain = validate_target_safety("https://api.worldmonitor.app/v1")
    assert result_subdomain["is_safe"] is False
    assert result_subdomain["safety_status"] == "RED"

def test_safety_guardrails_allows_sandbox():
    result_local = validate_target_safety("http://localhost:8080")
    assert result_local["is_safe"] is True
    assert result_local["safety_status"] == "GREEN"

    result_ip = validate_target_safety("http://127.0.0.1:8000")
    assert result_ip["is_safe"] is True
    assert result_ip["safety_status"] == "GREEN"

# 2. Cryptographic Hashing & Masking Tests
def test_sha256_evidence_hashing():
    data1 = {"finding": "BOLA", "id": 101}
    data2 = {"finding": "BOLA", "id": 101}
    assert compute_sha256(data1) == compute_sha256(data2)
    assert len(compute_sha256(data1)) == 64

def test_secret_masking():
    secret = "sk_live_94819283019283019283"
    masked = mask_secret(secret, visible_prefix=7)
    assert masked.startswith("sk_live")
    assert "********" in masked
    assert "94819283019283019283" not in masked

# 3. CVSS v3.1 Risk Engine Tests
def test_cvss_calculation():
    # Critical CVSS
    cvss_crit = calculate_cvss_v31(
        attack_vector="N", attack_complexity="L", privileges_required="N",
        user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H"
    )
    assert cvss_crit["score"] >= 9.0
    assert cvss_crit["severity"] == "CRITICAL"

    # High CVSS (BOLA/IDOR)
    cvss_high = calculate_cvss_v31(
        attack_vector="N", attack_complexity="L", privileges_required="L",
        user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"
    )
    assert 7.0 <= cvss_high["score"] <= 8.9
    assert cvss_high["severity"] == "HIGH"

# 4. Cross-Layer Correlation Engine Tests
def test_cross_layer_correlation():
    corr_engine = CorrelationEngine()
    sast_mock = [{
        "category": "Broken Authorization",
        "file_path": "server/routes/dossiers.ts",
        "line_number": 42,
        "code_snippet": "router.get('/dossiers/:id')"
    }]
    api_mock = [{
        "path": "/api/v1/user/intel-dossiers/{id}",
        "method": "GET",
        "auth_required": True
    }]
    auth_mock = [{
        "test_id": "AUTHZ-BOLA-CROSS-USER",
        "passed": False,
        "request": {"url": "http://localhost:8080/api/v1/user/intel-dossiers/dossier_101"},
        "response": {"status_code": 200, "body": {"dossier_id": "dossier_101"}}
    }]
    dast_mock = [{
        "id": "DAST-HDR-001",
        "title": "Missing Content-Security-Policy (CSP) Header",
        "category": "Security Headers",
        "severity": "MEDIUM",
        "cvss_score": 5.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe": "CWE-1021",
        "description": "Missing CSP"
    }]

    result = corr_engine.correlate(
        sast_findings=sast_mock,
        api_endpoints=api_mock,
        auth_results=auth_mock,
        dast_findings=dast_mock,
        dep_findings=[],
        secret_findings=[]
    )

    findings = result["correlated_findings"]
    assert len(findings) >= 2
    bola_finding = next(f for f in findings if f["category"] == "Broken Authorization")
    assert bola_finding["confidence"] == "VALIDATED"
    assert bola_finding["is_correlated"] is True
    assert "static_evidence" in bola_finding
    assert "runtime_evidence" in bola_finding
    assert result["assurance_score"] > 0

# 5. Retest Engine Tests
def test_retest_engine_before_and_after():
    import asyncio
    retest_engine = RetestEngine("http://localhost:8080")
    
    async def run_tests():
        # Test unpatched state
        res_unpatched = await retest_engine.execute_retest({"category": "Broken Authorization", "finding_code": "SS-001"}, is_patched=False)
        assert res_unpatched["after_status_code"] == 200
        assert res_unpatched["result"] == "STILL_VULNERABLE"

        # Test patched state
        res_patched = await retest_engine.execute_retest({"category": "Broken Authorization", "finding_code": "SS-001"}, is_patched=True)
        assert res_patched["before_status_code"] == 200
        assert res_patched["after_status_code"] == 403
        assert res_patched["result"] == "FIXED"
        assert res_patched["verified_status"] == "SECURITY CONTROL VERIFIED"

    asyncio.run(run_tests())

# 6. Report Generation Tests
def test_report_generation(tmp_path):
    report_service = ReportService(output_dir=str(tmp_path))
    sample_data = {
        "id": "test_assessment_101",
        "title": "Test Security Audit",
        "assurance_score": 85.0,
        "target": {"name": "Sandbox", "target_url": "http://localhost:8080"},
        "findings": [
            {
                "finding_code": "SS-001",
                "title": "Broken Authorization (BOLA)",
                "severity": "HIGH",
                "cvss_score": 8.1,
                "confidence": "VALIDATED",
                "cwe": "CWE-285",
                "description": "Validated BOLA issue",
                "remediation": {"recommended_fix": "Add tenant owner check"}
            }
        ]
    }

    json_file = report_service.generate_json_report(sample_data)
    assert os.path.exists(json_file)

    html_file = report_service.generate_html_report(sample_data)
    assert os.path.exists(html_file)

    pdf_file = report_service.generate_pdf_report(sample_data)
    assert os.path.exists(pdf_file)

# 7. Engine Unit Tests (SAST, API, Dependency, Secret, PoC, Remediation)
def test_sast_engine(tmp_path):
    # Create test vulnerable file in tmp_path
    vuln_code = """
    router.get('/dossiers/:id', (req, res) => {
        const item = db.get(req.params.id);
        res.json(item);
    });
    """
    test_file = tmp_path / "routes.ts"
    test_file.write_text(vuln_code, encoding="utf-8")

    sast = SASTEngine(str(tmp_path))
    findings = sast.scan()
    assert len(findings) > 0
    assert any(f["category"] == "Broken Authorization" for f in findings)

def test_dependency_scanner(tmp_path):
    pkg_json = '{"dependencies": {"axios": "1.6.8"}}'
    (tmp_path / "package.json").write_text(pkg_json, encoding="utf-8")

    dep_scanner = DependencyScanner(str(tmp_path))
    findings = dep_scanner.scan()
    assert len(findings) > 0
    assert any(f["package_name"] == "axios" for f in findings)

def test_secret_scanner(tmp_path):
    secret_code = 'const OPENAI_API_KEY = "sk-live-ab91f93849182374918273918237";'
    (tmp_path / "config.ts").write_text(secret_code, encoding="utf-8")

    sec_scanner = SecretScanner(str(tmp_path))
    findings = sec_scanner.scan()
    assert len(findings) > 0
    assert any("sk-" in f["masked_value"] for f in findings)
    assert "ab91f93849182374918273918237" not in findings[0]["masked_value"]

def test_safe_poc_engine_blocks_dangerous_targets():
    import asyncio
    poc_engine = SafePoCEngine("https://worldmonitor.app")
    
    async def run():
        res = await poc_engine.execute_poc({"target_url": "https://worldmonitor.app/admin"})
        assert res["status"] == "BLOCKED"
        assert "Safety violation" in res["error"]
        
    asyncio.run(run())

def test_remediation_engine():
    rem_engine = RemediationEngine("http://localhost:8080")
    res = rem_engine.apply_patch_to_sandbox("SS-001", "--- +++ patch")
    assert res["success"] is True
    assert res["target_environment"] == "ISOLATED_SANDBOX_ONLY"

# 8. Full Orchestration Test
def test_full_orchestration_cycle():
    import asyncio
    from backend.database.db import init_db
    from backend.database.repo import TargetRepo, AssessmentRepo
    from backend.services.orchestrator import ScanOrchestrator

    init_db()
    target = TargetRepo.create({
        "name": "Local Sandbox Automated Test",
        "repo_path": ".",
        "target_url": "http://localhost:8080",
        "is_approved_sandbox": 1,
        "safety_status": "GREEN"
    })

    assessment = AssessmentRepo.create({
        "target_id": target["id"],
        "title": "Automated Test Run",
        "status": "PENDING"
    })

    async def run_orchestration():
        orchestrator = ScanOrchestrator()
        completed = await orchestrator.execute_full_assessment(assessment["id"])
        assert completed["status"] == "COMPLETED"
        assert completed["assurance_score"] > 0
        assert len(completed["findings"]) > 0

    asyncio.run(run_orchestration())

# 9. FastAPI REST API Integration Tests
def test_api_routes():
    from fastapi.testclient import TestClient
    from backend.main import app
    client = TestClient(app)

    # Health check
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "HEALTHY"

    # Targets listing
    res_targets = client.get("/api/targets")
    assert res_targets.status_code == 200
    assert isinstance(res_targets.json(), list)

    # Safety rejection on production target via API
    res_unsafe = client.post("/api/targets", json={
        "name": "Public Target Attempt",
        "target_url": "https://worldmonitor.app"
    })
    assert res_unsafe.status_code == 400
    assert "Safety Policy" in res_unsafe.json()["detail"]

    # Dashboard metrics
    res_dash = client.get("/api/dashboard")
    assert res_dash.status_code == 200
    dash_data = res_dash.json()
    assert "assurance_score" in dash_data
    assert "severity_distribution" in dash_data

    # Security controls
    res_ctrl = client.get("/api/security-controls")
    assert res_ctrl.status_code == 200

    # Findings
    res_find = client.get("/api/findings")
    assert res_find.status_code == 200


