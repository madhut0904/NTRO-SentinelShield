#!/bin/bash
echo "=========================================================="
echo "  NTRO SentinelShield - Security Assurance Platform"
echo "=========================================================="

# 1. Start Sandbox Target
echo "[1/3] Starting Isolated Sandbox Target on http://localhost:8080..."
python3 sandbox/target_app.py &

# 2. Start FastAPI Backend
echo "[2/3] Starting FastAPI Backend on http://localhost:8000..."
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 &

# 3. Start Frontend
echo "[3/3] Starting Frontend Console on http://localhost:5173..."
cd frontend && npm run dev &

echo "=========================================================="
echo "  All services running in background!"
echo "  - Frontend: http://localhost:5173"
echo "  - Backend:  http://localhost:8000/docs"
echo "  - Sandbox:  http://localhost:8080"
echo "=========================================================="
wait
