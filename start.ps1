Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  NTRO SentinelShield - Security Assurance Platform" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Start Sandbox Digital Twin
Write-Host "[1/3] Starting Isolated Sandbox Target on http://localhost:8080..." -ForegroundColor Green
Start-Process python -ArgumentList "sandbox/target_app.py" -NoNewWindow

# 2. Start FastAPI Backend
Write-Host "[2/3] Starting FastAPI Backend on http://localhost:8000..." -ForegroundColor Green
Start-Process python -ArgumentList "-m uvicorn backend.main:app --host 0.0.0.0 --port 8000" -NoNewWindow

# 3. Start Frontend Console
Write-Host "[3/3] Starting React Frontend Console on http://localhost:5173..." -ForegroundColor Green
Set-Location frontend
Start-Process npm -ArgumentList "run dev" -NoNewWindow
Set-Location ..

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  All services started successfully!" -ForegroundColor Green
Write-Host "  - Frontend Console: http://localhost:5173" -ForegroundColor White
Write-Host "  - Backend Swagger:  http://localhost:8000/docs" -ForegroundColor White
Write-Host "  - Sandbox Target:   http://localhost:8080" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
