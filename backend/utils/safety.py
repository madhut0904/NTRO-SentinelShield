"""
NTRO SentinelShield - Target Safety & Boundary Guardrails
Enforces strict sandbox isolation: strictly prohibits public/production domains.
"""
from urllib.parse import urlparse
import ipaddress
import re

BLOCKED_DOMAINS = [
    "worldmonitor.app",
    "www.worldmonitor.app",
    "api.worldmonitor.app",
    "prod.worldmonitor.app"
]

ALLOWED_HOSTNAMES = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "host.docker.internal",
    "sandbox",
    "worldmonitor-sandbox",
    "testserver"
]

def is_private_ip(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

def validate_target_safety(target_url: str) -> dict:
    """
    Validates if a target URL complies with authorized sandbox testing policies.
    Returns dict with is_safe, safety_status (GREEN/RED), and reason.
    """
    if not target_url:
        return {
            "is_safe": False,
            "safety_status": "RED",
            "reason": "Target URL cannot be empty."
        }
    
    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    hostname = (parsed.hostname or "").lower()
    
    # 1. Hard Block for public production domain
    for blocked in BLOCKED_DOMAINS:
        if hostname == blocked or hostname.endswith(f".{blocked}"):
            return {
                "is_safe": False,
                "safety_status": "RED",
                "reason": f"SECURITY VIOLATION: Production target '{hostname}' is strictly forbidden. Testing is authorized ONLY against local Docker sandboxes."
            }
    
    # 2. Check Allowed Sandbox / Local Hostnames
    if hostname in ALLOWED_HOSTNAMES or is_private_ip(hostname):
        return {
            "is_safe": True,
            "safety_status": "GREEN",
            "reason": "Authorized isolated sandbox environment."
        }
    
    # 3. Check for local network ports / private regexes (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    if re.match(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", hostname):
        return {
            "is_safe": True,
            "safety_status": "GREEN",
            "reason": "Private sandbox network approved."
        }
        
    return {
        "is_safe": False,
        "safety_status": "RED",
        "reason": f"Target '{hostname}' is not an authorized private sandbox. Only localhost, 127.0.0.1, or isolated Docker targets are permitted."
    }
