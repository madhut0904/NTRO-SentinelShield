"""
NTRO SentinelShield - Sandbox Target Service (Digital Twin)
A local, isolated mock of World Monitor API with configurable vulnerability states for SIH jury demonstration.
"""
from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel
from typing import Optional, Dict
import uvicorn

app = FastAPI(title="World Monitor Sandbox Digital Twin")

# Internal state: whether the BOLA patch is currently applied
SYSTEM_STATE = {
    "bola_patched": False,
    "csp_enabled": False
}

SYNTHETIC_DOSSIERS = {
    "dossier_101": {
        "id": "dossier_101",
        "owner_id": "usr_alpha_101",
        "title": "Operation Northern Watch - Geopolitical Threat Matrix",
        "threat_level": "CRITICAL",
        "classified_notes": "SYNTHETIC: Satellite surveillance indicates elevated naval activity in sector 4.",
        "custom_alerts": ["GPS Jamming Detected", "Unregistered Transponder Alert"]
    },
    "dossier_202": {
        "id": "dossier_202",
        "owner_id": "usr_bravo_202",
        "title": "Commercial Flight Path Anomalies",
        "threat_level": "LOW",
        "classified_notes": "SYNTHETIC: Routine commercial aviation transponder latency.",
        "custom_alerts": []
    }
}

TOKEN_TO_USER = {
    "Bearer synthetic_jwt_user_a_alpha_token": "usr_alpha_101",
    "Bearer synthetic_jwt_user_b_bravo_token": "usr_bravo_202",
    "Bearer synthetic_jwt_admin_999_token": "usr_admin_999"
}

@app.middleware("http")
async def add_security_headers_middleware(request, call_next):
    response = await call_next(request)
    if SYSTEM_STATE["csp_enabled"]:
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.get("/")
def get_root():
    return {"status": "ONLINE", "service": "World Monitor Sandbox Target", "env": "ISOLATED_SANDBOX"}

@app.get("/api/v1/intel/feeds")
def get_intel_feeds():
    return {
        "feeds": [
            {"id": "feed_1", "region": "Strait of Hormuz", "activity": "Maritime Chokepoint Monitoring", "status": "ACTIVE"},
            {"id": "feed_2", "region": "Baltic Sea", "activity": "Subsea Infrastructure Telemetry", "status": "NORMAL"}
        ]
    }

# THE CORE DEMO ENDPOINT: Broken Object Level Authorization
@app.get("/api/v1/user/intel-dossiers/{dossier_id}")
def get_intel_dossier(dossier_id: str, authorization: Optional[str] = Header(None)):
    if not authorization or authorization not in TOKEN_TO_USER:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    current_user_id = TOKEN_TO_USER[authorization]
    dossier = SYNTHETIC_DOSSIERS.get(dossier_id)
    if not dossier:
        raise HTTPException(status_code=404, detail="Dossier not found")

    # In Vulnerable State: Ignores owner check and returns confidential dossier!
    if not SYSTEM_STATE["bola_patched"]:
        return dossier

    # In Patched State: Strict Tenant / Ownership Boundary Enforcement
    if dossier["owner_id"] != current_user_id and current_user_id != "usr_admin_999":
        raise HTTPException(status_code=403, detail="Access Denied: Resource belongs to another tenant")

    return dossier

# Sandbox Control Endpoints (For Live Demo Patch Application)
@app.post("/sandbox/patch/apply")
def apply_sandbox_patch():
    SYSTEM_STATE["bola_patched"] = True
    SYSTEM_STATE["csp_enabled"] = True
    return {"status": "SUCCESS", "message": "Sandbox updated: BOLA check & CSP headers enforced."}

@app.post("/sandbox/patch/reset")
def reset_sandbox():
    SYSTEM_STATE["bola_patched"] = False
    SYSTEM_STATE["csp_enabled"] = False
    return {"status": "SUCCESS", "message": "Sandbox reset to baseline vulnerable state."}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
