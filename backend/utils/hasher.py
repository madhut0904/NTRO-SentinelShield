"""
NTRO SentinelShield - Cryptographic Hashing Engine
Computes immutable SHA-256 signatures for evidence verification, audit trails, and secret masking.
"""
import hashlib
import json
from typing import Any

def compute_sha256(data: Any) -> str:
    """
    Computes a deterministic SHA-256 checksum for arbitrary strings, dicts, or binary data.
    """
    if isinstance(data, dict) or isinstance(data, list):
        serialized = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    elif isinstance(data, str):
        serialized = data.encode("utf-8")
    elif isinstance(data, bytes):
        serialized = data
    else:
        serialized = str(data).encode("utf-8")
        
    return hashlib.sha256(serialized).hexdigest()

def mask_secret(secret_val: str, visible_prefix: int = 6) -> str:
    """
    Sanitizes confidential secrets for UI/evidence display.
    Example: 'sk_live_938491823791' -> 'sk_liv********'
    """
    if not secret_val or len(secret_val) <= visible_prefix:
        return "********"
    return secret_val[:visible_prefix] + "********"
