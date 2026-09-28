# NTRO SentinelShield

**Security Assessment & Continuous Assurance Platform for World Monitor**  
*SIH 2026 – Problem Statement ID 26163 (Theme: Smart Automation)*

---

## 🛡️ Executive Summary & Core Innovation

Traditional vulnerability scanners operate in isolation—SAST generates unverified syntactic alerts, while DAST produces uncontextualized runtime anomalies.

**NTRO SentinelShield introduces Cross-Layer Security Correlation:**
It synthesizes:
$$\text{Static SAST Finding} + \text{Discovered API Endpoint} + \text{Controlled Auth Identity} + \text{Runtime DAST Response} \longrightarrow \mathbf{Validated\ High\text{-}Confidence\ Finding}$$

### Closed-Loop Assurance Pipeline:
$$\text{FIND} \longrightarrow \text{PROVE} \longrightarrow \text{CORRELATE} \longrightarrow \text{SCORE} \longrightarrow \text{REMEDIATE} \longrightarrow \text{RETEST} \longrightarrow \text{VERIFY}$$

---

## 🔒 Hard Target Safety Guardrails

SentinelShield enforces strict hard isolation policies:
- **STRICTLY PROHIBITED:** Any scanning or probing against public production domains (`https://www.worldmonitor.app`).
- **STRICTLY ENFORCED:** Testing runs exclusively against isolated local Docker sandboxes (`localhost`, `127.0.0.1`, private Docker bridges) using synthetic test accounts (`ADMIN_TEST`, `USER_A`, `USER_B`, `ANONYMOUS`).
- **NON-DESTRUCTIVE:** Safe PoC verification without data deletion or DoS.

---

## 🚀 Key Architectural Modules

1. **Target Manager (`/api/targets`):** Automatically validates target URLs against allowlists, rejecting public domains with a RED alert and approving local sandboxes with a GREEN badge.
2. **SAST Engine (`backend/engines/sast/`):** AST and regex analysis for BOLA/IDOR, hardcoded secrets, dangerous commands, and missing headers.
3. **API Security Engine (`backend/engines/api_security/`):** Discovers routes, methods, parameter schemas, and exposed sensitive fields.
4. **Auth & Identity Matrix (`backend/engines/auth_engine/`):** Multi-tenant synthetic privilege boundary testing.
5. **DAST Engine (`backend/engines/dast/`):** Non-destructive HTTP probe testing CSP, HSTS, CORS origins, and cookies.
6. **Correlation Engine (`backend/engines/correlation/`):** Combines static code signatures with runtime HTTP responses to compute the internal **Security Assurance Score (0-100)**.
7. **Evidence Vault (`backend/models/models.py`):** Cryptographic SHA-256 seal on all request/response pairs and AST code snippets for full forensic auditability.
8. **Safe PoC Engine (`backend/engines/poc/`):** Generates reproducible non-destructive proof-of-concept tests.
9. **Remediation & Retest Engine (`backend/engines/remediation/`, `backend/engines/retest/`):** Generates unified Git diff patches, applies them strictly inside the sandbox, and demonstrates BEFORE (200 OK ❌) vs AFTER (403 Forbidden ✓) control verification.
10. **Report Engine (`backend/services/report_service.py`):** Compiles VAPT reports in PDF, HTML, and JSON formats.

---

## ⚡ Quickstart & Deployment

### 🐳 Option 1: Docker Compose (One-Command Launch)
```bash
# Build and start all 3 services in isolated private network
docker compose up -d --build
```
- **SOC Console:** [http://localhost:5173](http://localhost:5173)
- **FastAPI API & Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Isolated Sandbox:** [http://localhost:8080](http://localhost:8080)

### 💻 Option 2: Local One-Click Startup
```powershell
# Windows (PowerShell)
.\start.ps1

# Linux / macOS (Bash)
chmod +x start.sh && ./start.sh
```

### 🧪 Option 3: Run Automated Test Suite
```bash
python -m pytest tests/ -v
```

For comprehensive cloud, VPS, and production deployment instructions, see [DEPLOYMENT.md](file:///c:/Users/MADHU%20T/OneDrive/Projects/NTRO/DEPLOYMENT.md).

---

## 📋 Target Registration for Authentic World Monitor
To audit the authentic cloned repository of [`koala73/worldmonitor`](https://github.com/koala73/worldmonitor):
- **Target Name:** `World Monitor Sandbox (koala73/worldmonitor)`
- **Target URL:** `http://localhost:8080`
- **Repository Path:** `C:\Users\MADHU T\OneDrive\Projects\worldmonitor`
- **Docker Compose Path:** `./sandbox/docker-compose.yml`
- **Branch:** `main` | **Environment:** `SANDBOX`

