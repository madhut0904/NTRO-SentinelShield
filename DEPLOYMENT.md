# NTRO SentinelShield - Deployment Guide

**Security Assessment & Continuous Assurance Platform for World Monitor**  
*SIH 2026 – Problem Statement ID 26163*

---

## ?? Option 1: Docker Compose (Recommended for Production & Judges)

Deploy the entire full-stack ecosystem (**Frontend**, **FastAPI Backend**, and **Isolated Sandbox**) with a single command.

### Prerequisites
- [Docker](https://www.docker.com/) (v24+) & [Docker Compose](https://docs.docker.com/compose/) (v2+)

### 1. Clone Repository & Launch
`ash
git clone https://github.com/madhut0904/NTRO-SentinelShield.git
cd NTRO-SentinelShield

# Build and start all 3 services in background
docker compose up -d --build
`

### 2. Verify Services
`ash
docker compose ps
`

| Container | URL | Port | Description |
| :--- | :--- | :--- | :--- |
| **sentinelshield-frontend** | http://localhost:5173 | 80 -> 5173 | React + Nginx SOC Console with NTRO Emblem |
| **sentinelshield-backend** | http://localhost:8000 | 8000 | FastAPI 15-Stage Engine & Swagger Docs (/docs) |
| **sentinelshield-sandbox** | http://localhost:8080 | 8080 | Isolated World Monitor Digital Twin |

### 3. Stop Containers
`ash
docker compose down
`

---

## ?? Option 2: Local One-Click Scripts (Development Mode)

### Prerequisites
- Python 3.10+
- Node.js 18+ & npm

### On Windows (PowerShell):
`powershell
# 1. Install dependencies (First time only)
pip install -r backend/requirements.txt
cd frontend && npm install && cd ..

# 2. Start all services
.\start.ps1
`

### On Linux / macOS (Bash):
`ash
chmod +x start.sh
./start.sh
`

---

## ?? Option 3: Cloud VPS / Dedicated Server (Ubuntu 22.04 / 24.04)

### 1. Server Setup
`ash
sudo apt update && sudo apt install -y docker.io docker-compose git curl
sudo systemctl enable --now docker
`

### 2. Clone and Start
`ash
git clone https://github.com/madhut0904/NTRO-SentinelShield.git /opt/sentinelshield
cd /opt/sentinelshield

# Start via Docker Compose
sudo docker compose up -d --build
`

### 3. Firewall Configuration (UFW)
`ash
sudo ufw allow 80/tcp
sudo ufw allow 5173/tcp
sudo ufw allow 8000/tcp
sudo ufw allow 8080/tcp
sudo ufw enable
`

---

## ?? Option 4: Run Automated Verification Tests

Run the test suite to verify all security engines, safety guardrails, CVSS calculators, SHA-256 evidence hashing, and API routes:

`ash
python -m pytest tests/ -v
`

---

## ?? Target Safety Policy
SentinelShield enforces strict hard isolation:
- **BLOCKED (RED):** https://worldmonitor.app and public domains are immediately rejected by safety middleware.
- **APPROVED (GREEN):** Only local sandboxes (http://localhost:8080, 127.0.0.1, private Docker bridge) are permitted for security assessment.
