"""
NTRO SentinelShield - Backend Application Entrypoint
"""
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.database.db import init_db
from backend.database.repo import TargetRepo, AssessmentRepo
from backend.api.routes import router
from backend.services.orchestrator import ScanOrchestrator

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database schema
    init_db()
    yield

app = FastAPI(
    title="NTRO SentinelShield API",
    description="Continuous Security Assurance & Cross-Layer Correlation Platform for World Monitor (SIH 2026)",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.get("/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": "NTRO SentinelShield Security Assurance Engine",
        "environment": "SANDBOX ONLY",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
