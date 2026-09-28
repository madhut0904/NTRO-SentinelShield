"""
NTRO SentinelShield - Secret & Credential Detection Scanner
Detects API keys, tokens, passwords, and private keys with high-entropy regex and safe masking.
"""
import os
import re
import math
from typing import List, Dict, Any
from backend.utils.hasher import compute_sha256, mask_secret

SECRET_PATTERNS = [
    {
        "type": "OpenAI / Anthropic API Key",
        "regex": r"(?:sk-(?:live|proj|ant)-[A-Za-z0-9_\-]{20,})",
        "min_entropy": 3.0
    },
    {
        "type": "AWS Access Key ID",
        "regex": r"(?:AKIA[0-9A-Z]{16})",
        "min_entropy": 2.5
    },
    {
        "type": "Generic Bearer / JWT Secret",
        "regex": r"(?:jwt_secret|api_secret|session_secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]",
        "min_entropy": 3.2
    },
    {
        "type": "Database Connection URI with Credentials",
        "regex": r"(?:postgres|mysql|redis)://[^:]+:([^@]+)@",
        "min_entropy": 2.5
    }
]

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return round(entropy, 2)

class SecretScanner:
    def __init__(self, target_path: str):
        self.target_path = target_path

    def scan(self) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(self.target_path):
            return findings

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", ".venv", "dist", "build"]]
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.target_path).replace("\\", "/")
                
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_idx, line in enumerate(f, start=1):
                            for pattern_def in SECRET_PATTERNS:
                                matches = re.finditer(pattern_def["regex"], line)
                                for match in matches:
                                    raw_secret = match.group(1) if match.groups() else match.group(0)
                                    entropy = calculate_shannon_entropy(raw_secret)
                                    
                                    if entropy >= pattern_def["min_entropy"]:
                                        masked = mask_secret(raw_secret, visible_prefix=4)
                                        sha = compute_sha256(raw_secret)
                                        
                                        findings.append({
                                            "file_path": rel_path,
                                            "line_number": line_idx,
                                            "secret_type": pattern_def["type"],
                                            "masked_value": masked,
                                            "entropy_score": entropy,
                                            "sha256_hash": sha
                                        })
                except Exception:
                    continue

        return findings
