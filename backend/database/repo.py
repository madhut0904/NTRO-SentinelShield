"""
NTRO SentinelShield - Data Access Repository
CRUD operations for SQLite persistence.
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from backend.database.db import get_connection

def gen_id():
    return str(uuid.uuid4())

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def json_dumps(data):
    return json.dumps(data, default=str)

def json_loads(data, fallback=None):
    if not data:
        return fallback if fallback is not None else {}
    if isinstance(data, (dict, list)):
        return data
    try:
        return json.loads(data)
    except:
        return fallback if fallback is not None else {}

class TargetRepo:
    @staticmethod
    def create(data: Dict[str, Any]) -> Dict[str, Any]:
        conn = get_connection()
        cur = conn.cursor()
        t_id = data.get("id", gen_id())
        created_at = data.get("created_at", now_iso())
        cur.execute("""
        INSERT INTO targets (id, name, repo_path, docker_compose_path, branch, environment, target_url, is_approved_sandbox, safety_status, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            t_id, data["name"], data.get("repo_path"), data.get("docker_compose_path"),
            data.get("branch", "main"), data.get("environment", "SANDBOX"),
            data["target_url"], data.get("is_approved_sandbox", 1),
            data.get("safety_status", "GREEN"), data.get("description"), created_at
        ))
        conn.commit()
        conn.close()
        return TargetRepo.get(t_id)

    @staticmethod
    def get(target_id: str) -> Optional[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["is_approved_sandbox"] = bool(d["is_approved_sandbox"])
        return d

    @staticmethod
    def list_all() -> List[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM targets ORDER BY created_at DESC")
        rows = cur.fetchall()
        conn.close()
        res = []
        for r in rows:
            d = dict(r)
            d["is_approved_sandbox"] = bool(d["is_approved_sandbox"])
            res.append(d)
        return res

class FindingRepo:
    @staticmethod
    def create(data: Dict[str, Any]) -> Dict[str, Any]:
        conn = get_connection()
        cur = conn.cursor()
        f_id = data.get("id", gen_id())
        now = now_iso()
        cur.execute("""
        INSERT OR REPLACE INTO findings (
            id, finding_code, assessment_id, title, category, severity, cvss_score, cvss_vector,
            cwe, file_path, line_number, code_snippet, description, status, confidence,
            is_correlated, static_evidence, runtime_evidence, api_evidence, auth_context,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f_id, data["finding_code"], data["assessment_id"], data["title"], data["category"],
            data["severity"], data.get("cvss_score", 0.0), data.get("cvss_vector"),
            data.get("cwe", "CWE-200"), data.get("file_path"), data.get("line_number"),
            data.get("code_snippet"), data["description"], data.get("status", "OPEN"),
            data.get("confidence", "HIGH"), int(data.get("is_correlated", 1)),
            json_dumps(data.get("static_evidence", {})), json_dumps(data.get("runtime_evidence", {})),
            json_dumps(data.get("api_evidence", {})), json_dumps(data.get("auth_context", {})),
            data.get("created_at", now), now
        ))
        conn.commit()
        conn.close()
        return FindingRepo.get(f_id)

    @staticmethod
    def get(finding_id: str) -> Optional[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM findings WHERE id = ? OR finding_code = ?", (finding_id, finding_id))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["is_correlated"] = bool(d["is_correlated"])
        d["static_evidence"] = json_loads(d["static_evidence"], {})
        d["runtime_evidence"] = json_loads(d["runtime_evidence"], {})
        d["api_evidence"] = json_loads(d["api_evidence"], {})
        d["auth_context"] = json_loads(d["auth_context"], {})
        
        # Attach PoC, Remediation, Retest, Evidence
        d["poc"] = PoCRepo.get_by_finding(d["id"])
        d["remediation"] = RemediationRepo.get_by_finding(d["id"])
        d["retests"] = RetestRepo.list_by_finding(d["id"])
        d["evidences"] = EvidenceRepo.list_by_finding(d["id"])
        return d

    @staticmethod
    def list_all(assessment_id: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if assessment_id:
            query += " AND assessment_id = ?"
            params.append(assessment_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY cvss_score DESC"
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()
        res = []
        for r in rows:
            d = dict(r)
            d["is_correlated"] = bool(d["is_correlated"])
            d["static_evidence"] = json_loads(d["static_evidence"], {})
            d["runtime_evidence"] = json_loads(d["runtime_evidence"], {})
            d["api_evidence"] = json_loads(d["api_evidence"], {})
            d["auth_context"] = json_loads(d["auth_context"], {})
            d["poc"] = PoCRepo.get_by_finding(d["id"])
            d["remediation"] = RemediationRepo.get_by_finding(d["id"])
            d["retests"] = RetestRepo.list_by_finding(d["id"])
            d["evidences"] = EvidenceRepo.list_by_finding(d["id"])
            res.append(d)
        return res

    @staticmethod
    def update_status(finding_id: str, status: str):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE findings SET status = ?, updated_at = ? WHERE id = ? OR finding_code = ?", (status, now_iso(), finding_id, finding_id))
        conn.commit()
        conn.close()

class AssessmentRepo:
    @staticmethod
    def create(data: Dict[str, Any]) -> Dict[str, Any]:
        conn = get_connection()
        cur = conn.cursor()
        a_id = data.get("id", gen_id())
        now = now_iso()
        cur.execute("""
        INSERT INTO assessments (id, target_id, title, status, assurance_score, score_breakdown, summary, created_at, completed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            a_id, data["target_id"], data["title"], data.get("status", "PENDING"),
            data.get("assurance_score", 0.0), json_dumps(data.get("score_breakdown", {})),
            data.get("summary"), data.get("created_at", now), data.get("completed_at")
        ))
        conn.commit()
        conn.close()
        return AssessmentRepo.get(a_id)

    @staticmethod
    def get(assessment_id: str) -> Optional[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["score_breakdown"] = json_loads(d["score_breakdown"], {})
        d["target"] = TargetRepo.get(d["target_id"])
        d["findings"] = FindingRepo.list_all(assessment_id=d["id"])
        d["controls"] = ControlRepo.list_by_assessment(d["id"])
        return d

    @staticmethod
    def list_all() -> List[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM assessments ORDER BY created_at DESC")
        rows = cur.fetchall()
        conn.close()
        res = []
        for r in rows:
            d = dict(r)
            d["score_breakdown"] = json_loads(d["score_breakdown"], {})
            d["target"] = TargetRepo.get(d["target_id"])
            res.append(d)
        return res

    @staticmethod
    def update(assessment_id: str, data: Dict[str, Any]):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
        UPDATE assessments
        SET status = ?, assurance_score = ?, score_breakdown = ?, summary = ?, completed_at = ?
        WHERE id = ?
        """, (
            data.get("status", "COMPLETED"), data.get("assurance_score", 82.0),
            json_dumps(data.get("score_breakdown", {})), data.get("summary"),
            data.get("completed_at", now_iso()), assessment_id
        ))
        conn.commit()
        conn.close()

class ControlRepo:
    @staticmethod
    def create(data: Dict[str, Any]):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO security_controls (id, assessment_id, control_id, name, category, expected, tested, result, evidence_id, confidence, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("id", gen_id()), data["assessment_id"], data["control_id"], data["name"],
            data["category"], data["expected"], int(data.get("tested", 1)),
            data.get("result", "PASS"), data.get("evidence_id"),
            data.get("confidence", "HIGH"), data.get("description")
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def list_by_assessment(assessment_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        if assessment_id:
            cur.execute("SELECT * FROM security_controls WHERE assessment_id = ?", (assessment_id,))
        else:
            cur.execute("SELECT * FROM security_controls")
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]

class PoCRepo:
    @staticmethod
    def create(data: Dict[str, Any]):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO poc_tests (id, finding_id, title, purpose, target_url, method, test_identity, headers, payload, expected_result, actual_result, status, is_safe, executed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("id", gen_id()), data["finding_id"], data["title"], data["purpose"],
            data["target_url"], data.get("method", "GET"), data.get("test_identity", "USER_B"),
            json_dumps(data.get("headers", {})), json_dumps(data.get("payload", {})),
            data["expected_result"], data.get("actual_result"), data.get("status", "READY"),
            int(data.get("is_safe", 1)), data.get("executed_at", now_iso())
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def get_by_finding(finding_id: str) -> Optional[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM poc_tests WHERE finding_id = ?", (finding_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["headers"] = json_loads(d["headers"], {})
        d["payload"] = json_loads(d["payload"], {})
        d["is_safe"] = bool(d["is_safe"])
        return d

    @staticmethod
    def update_result(finding_id: str, status: str, actual_result: str):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE poc_tests SET status = ?, actual_result = ?, executed_at = ? WHERE finding_id = ?", (status, actual_result, now_iso(), finding_id))
        conn.commit()
        conn.close()

class RemediationRepo:
    @staticmethod
    def create(data: Dict[str, Any]):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO remediations (id, finding_id, problem, root_cause, recommended_fix, safe_patch_diff, security_impact, applied_to_sandbox, applied_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("id", gen_id()), data["finding_id"], data["problem"], data["root_cause"],
            data["recommended_fix"], data["safe_patch_diff"], data["security_impact"],
            int(data.get("applied_to_sandbox", 0)), data.get("applied_at"), now_iso()
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def get_by_finding(finding_id: str) -> Optional[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM remediations WHERE finding_id = ?", (finding_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["applied_to_sandbox"] = bool(d["applied_to_sandbox"])
        return d

    @staticmethod
    def mark_applied(finding_id: str):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE remediations SET applied_to_sandbox = 1, applied_at = ? WHERE finding_id = ?", (now_iso(), finding_id))
        conn.commit()
        conn.close()

class RetestRepo:
    @staticmethod
    def create(data: Dict[str, Any]):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
        INSERT OR REPLACE INTO retests (id, finding_id, before_status_code, before_response, after_status_code, after_response, result, verified_status, retest_timestamp, execution_notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("id", gen_id()), data["finding_id"], data["before_status_code"],
            data.get("before_response"), data["after_status_code"], data.get("after_response"),
            data.get("result", "FIXED"), data.get("verified_status", "SECURITY CONTROL VERIFIED"),
            data.get("retest_timestamp", now_iso()), data.get("execution_notes")
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def list_by_finding(finding_id: str) -> List[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM retests WHERE finding_id = ? ORDER BY retest_timestamp DESC", (finding_id,))
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]

class EvidenceRepo:
    @staticmethod
    def create(data: Dict[str, Any]):
        conn = get_connection()
        cur = conn.cursor()
        ev_id = data.get("id", gen_id())
        ev_code = data.get("evidence_code", f"EV-{ev_id[:6].upper()}")
        cur.execute("""
        INSERT OR REPLACE INTO evidence (id, evidence_code, finding_id, timestamp, test_identity, request_data, response_data, source_file, code_line, log_snippet, sha256_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ev_id, ev_code, data["finding_id"], now_iso(),
            data.get("test_identity", "ANONYMOUS"), json_dumps(data.get("request_data", {})),
            json_dumps(data.get("response_data", {})), data.get("source_file"),
            data.get("code_line"), data.get("log_snippet"), data["sha256_hash"]
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def list_by_finding(finding_id: str) -> List[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM evidence WHERE finding_id = ?", (finding_id,))
        rows = cur.fetchall()
        conn.close()
        res = []
        for r in rows:
            d = dict(r)
            d["request_data"] = json_loads(d["request_data"], {})
            d["response_data"] = json_loads(d["response_data"], {})
            res.append(d)
        return res

class EndpointRepo:
    @staticmethod
    def create(data: Dict[str, Any]):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO endpoints (id, assessment_id, method, path, auth_required, auth_mechanism, parameters, sensitive_fields, risk_level, discovered_via)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("id", gen_id()), data["assessment_id"], data["method"], data["path"],
            int(data.get("auth_required", 0)), data.get("auth_mechanism", "None"),
            json_dumps(data.get("parameters", [])), json_dumps(data.get("sensitive_fields", [])),
            data.get("risk_level", "LOW"), data.get("discovered_via", "STATIC_ROUTER")
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def list_by_assessment(assessment_id: str) -> List[Dict[str, Any]]:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM endpoints WHERE assessment_id = ?", (assessment_id,))
        rows = cur.fetchall()
        conn.close()
        res = []
        for r in rows:
            d = dict(r)
            d["parameters"] = json_loads(d["parameters"], [])
            d["sensitive_fields"] = json_loads(d["sensitive_fields"], [])
            d["auth_required"] = bool(d["auth_required"])
            res.append(d)
        return res

class ReportRepo:
    @staticmethod
    def create(data: Dict[str, Any]) -> Dict[str, Any]:
        conn = get_connection()
        cur = conn.cursor()
        r_id = data.get("id", gen_id())
        now = now_iso()
        cur.execute("""
        INSERT INTO reports (id, assessment_id, report_type, title, file_path, content_summary, generated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            r_id, data["assessment_id"], data["report_type"], data["title"],
            data.get("file_path"), data.get("content_summary"), now
        ))
        conn.commit()
        conn.close()
        return {"id": r_id, "generated_at": now, **data}

class AuditRepo:
    @staticmethod
    def log(user: str, action: str, target: str, details: Dict[str, Any] = None):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO audit_logs (id, user, action, target, timestamp, result, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (gen_id(), user, action, target, now_iso(), "SUCCESS", json_dumps(details or {})))
        conn.commit()
        conn.close()
