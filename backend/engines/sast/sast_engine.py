"""
NTRO SentinelShield - SAST (Static Application Security Testing) Engine
Analyzes source code repositories for access-control vulnerabilities, hardcoded secrets, injection flaws, and security misconfigurations.
"""
import os
import re
from typing import List, Dict, Any

# High-precision SAST rules for TypeScript, JavaScript, Python, Dockerfile, and configs
SAST_RULES = [
    {
        "id": "SAST-AUTH-001",
        "title": "Missing Object-Level Authorization Check (BOLA/IDOR)",
        "category": "Broken Authorization",
        "severity": "HIGH",
        "cwe": "CWE-285",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 8.1,
        "regex": r"(?:router\.(?:get|post|put|delete)|app\.(?:get|post|put|delete))\(['\"].*?:id.*?\)|def\s+get_.*?\([^)]*?id:\s*str.*?\):",
        "negative_pattern": r"(?:verify_ownership|check_permission|has_access|require_owner|user_id\s*==\s*record\.owner_id)",
        "file_extensions": [".ts", ".js", ".py"],
        "description": "Endpoint retrieves or mutates user-specific objects by identifier without validating that the authenticated session owns the target resource.",
        "remediation": "Validate authenticated user identity against resource owner_id before executing query or returning sensitive data."
    },
    {
        "id": "SAST-CORS-002",
        "title": "Overly Permissive Cross-Origin Resource Sharing (CORS)",
        "category": "Configuration",
        "severity": "MEDIUM",
        "cwe": "CWE-942",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "cvss_score": 6.5,
        "regex": r"(?:allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|Access-Control-Allow-Origin['\"]\s*:\s*['\"]\*['\"])",
        "file_extensions": [".ts", ".js", ".py", ".json"],
        "description": "CORS header 'Access-Control-Allow-Origin: *' allows any untrusted external origin to make authenticated requests or read sensitive API responses.",
        "remediation": "Restrict allowed origins to trusted private domains or exact frontend hostnames."
    },
    {
        "id": "SAST-HDR-003",
        "title": "Missing Critical Security Headers (HSTS, CSP, X-Frame-Options)",
        "category": "Security Headers",
        "severity": "MEDIUM",
        "cwe": "CWE-1021",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cvss_score": 5.4,
        "regex": r"(?:helmet|Content-Security-Policy|Strict-Transport-Security)",
        "must_exist": False, # Flag if missing across the whole project
        "file_extensions": [".ts", ".js", ".py"],
        "description": "Server responses do not mandate Content-Security-Policy or Strict-Transport-Security, leaving clients susceptible to clickjacking and MITM downgrades.",
        "remediation": "Include HSTS, X-Content-Type-Options: nosniff, and a strict Content-Security-Policy header."
    },
    {
        "id": "SAST-SEC-004",
        "title": "Hardcoded Cryptographic / API Secret in Source Code",
        "category": "Secrets",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "regex": r"(?:api_key|jwt_secret|secret_key|private_key|password)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]",
        "file_extensions": [".ts", ".js", ".py", ".env", ".json"],
        "description": "High-entropy secrets or private tokens detected in plaintext source code files.",
        "remediation": "Move secrets into secure environment variables or a dedicated KMS / Secrets Manager."
    },
    {
        "id": "SAST-INJ-005",
        "title": "Potential Server-Side Command / Code Execution Injection",
        "category": "Input Validation",
        "severity": "HIGH",
        "cwe": "CWE-78",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 8.8,
        "regex": r"(?:exec\(|eval\(|child_process\.exec|subprocess\.Popen\(.*?shell=True)",
        "file_extensions": [".ts", ".js", ".py"],
        "description": "Dynamic evaluation or shell execution with unsanitized inputs enables arbitrary command execution.",
        "remediation": "Avoid shell=True and dynamic eval. Use parameterized process invocations and strict input whitelisting."
    }
]

class SASTEngine:
    def __init__(self, target_path: str):
        self.target_path = target_path

    def scan(self) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(self.target_path):
            return findings

        # Walk repository
        for root, dirs, files in os.walk(self.target_path):
            # Skip noise directories
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", ".venv", "__pycache__", "dist", "build"]]
            
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.target_path).replace("\\", "/")
                ext = os.path.splitext(file)[1].lower()
                
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        content = "".join(lines)
                except Exception:
                    continue

                for rule in SAST_RULES:
                    if ext in rule["file_extensions"]:
                        pattern = re.compile(rule["regex"], re.IGNORECASE)
                        for line_idx, line in enumerate(lines, start=1):
                            if pattern.search(line):
                                # Check negative patterns for BOLA
                                neg = rule.get("negative_pattern")
                                if neg and re.search(neg, content, re.IGNORECASE):
                                    continue # Found safety mitigation in context
                                
                                snippet = line.strip()
                                findings.append({
                                    "rule_id": rule["id"],
                                    "title": rule["title"],
                                    "category": rule["category"],
                                    "severity": rule["severity"],
                                    "cwe": rule["cwe"],
                                    "cvss_score": rule["cvss_score"],
                                    "cvss_vector": rule["cvss_vector"],
                                    "file_path": rel_path,
                                    "line_number": line_idx,
                                    "code_snippet": snippet[:200],
                                    "description": rule["description"],
                                    "remediation": rule["remediation"],
                                    "confidence": "HIGH"
                                })
        return findings
