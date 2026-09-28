"""
NTRO SentinelShield - Pure Python SQLite Database Engine
Zero-dependency, high-speed SQLite persistence with complete transaction safety.
"""
import sqlite3
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

DB_FILE = os.getenv("DATABASE_FILE", "./sentinelshield.db")

def get_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Create Tables
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS targets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        repo_path TEXT,
        docker_compose_path TEXT,
        branch TEXT DEFAULT 'main',
        environment TEXT DEFAULT 'SANDBOX',
        target_url TEXT NOT NULL,
        is_approved_sandbox BOOLEAN DEFAULT 1,
        safety_status TEXT DEFAULT 'GREEN',
        description TEXT,
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS assessments (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        title TEXT NOT NULL,
        status TEXT DEFAULT 'PENDING',
        assurance_score REAL DEFAULT 0.0,
        score_breakdown TEXT,
        summary TEXT,
        created_at TEXT,
        completed_at TEXT,
        FOREIGN KEY(target_id) REFERENCES targets(id)
    );

    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        finding_code TEXT UNIQUE NOT NULL,
        assessment_id TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL DEFAULT 0.0,
        cvss_vector TEXT,
        cwe TEXT,
        file_path TEXT,
        line_number INTEGER,
        code_snippet TEXT,
        description TEXT NOT NULL,
        status TEXT DEFAULT 'OPEN',
        confidence TEXT DEFAULT 'MEDIUM',
        is_correlated BOOLEAN DEFAULT 1,
        static_evidence TEXT,
        runtime_evidence TEXT,
        api_evidence TEXT,
        auth_context TEXT,
        created_at TEXT,
        updated_at TEXT,
        FOREIGN KEY(assessment_id) REFERENCES assessments(id)
    );

    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        evidence_code TEXT UNIQUE NOT NULL,
        finding_id TEXT NOT NULL,
        timestamp TEXT,
        test_identity TEXT,
        request_data TEXT,
        response_data TEXT,
        source_file TEXT,
        code_line INTEGER,
        log_snippet TEXT,
        sha256_hash TEXT NOT NULL,
        FOREIGN KEY(finding_id) REFERENCES findings(id)
    );

    CREATE TABLE IF NOT EXISTS poc_tests (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        title TEXT NOT NULL,
        purpose TEXT NOT NULL,
        target_url TEXT NOT NULL,
        method TEXT DEFAULT 'GET',
        test_identity TEXT DEFAULT 'USER_B',
        headers TEXT,
        payload TEXT,
        expected_result TEXT NOT NULL,
        actual_result TEXT,
        status TEXT DEFAULT 'READY',
        is_safe BOOLEAN DEFAULT 1,
        executed_at TEXT,
        FOREIGN KEY(finding_id) REFERENCES findings(id)
    );

    CREATE TABLE IF NOT EXISTS remediations (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        problem TEXT NOT NULL,
        root_cause TEXT NOT NULL,
        recommended_fix TEXT NOT NULL,
        safe_patch_diff TEXT NOT NULL,
        security_impact TEXT NOT NULL,
        applied_to_sandbox BOOLEAN DEFAULT 0,
        applied_at TEXT,
        created_at TEXT,
        FOREIGN KEY(finding_id) REFERENCES findings(id)
    );

    CREATE TABLE IF NOT EXISTS retests (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        before_status_code INTEGER NOT NULL,
        before_response TEXT,
        after_status_code INTEGER NOT NULL,
        after_response TEXT,
        result TEXT DEFAULT 'FIXED',
        verified_status TEXT DEFAULT 'SECURITY CONTROL VERIFIED',
        retest_timestamp TEXT,
        execution_notes TEXT,
        FOREIGN KEY(finding_id) REFERENCES findings(id)
    );

    CREATE TABLE IF NOT EXISTS security_controls (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL,
        control_id TEXT NOT NULL,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        expected TEXT NOT NULL,
        tested BOOLEAN DEFAULT 1,
        result TEXT DEFAULT 'NOT_TESTED',
        evidence_id TEXT,
        confidence TEXT DEFAULT 'HIGH',
        description TEXT,
        FOREIGN KEY(assessment_id) REFERENCES assessments(id)
    );

    CREATE TABLE IF NOT EXISTS endpoints (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        auth_required BOOLEAN DEFAULT 0,
        auth_mechanism TEXT DEFAULT 'None',
        parameters TEXT,
        sensitive_fields TEXT,
        risk_level TEXT DEFAULT 'LOW',
        discovered_via TEXT DEFAULT 'SAST_ROUTER',
        FOREIGN KEY(assessment_id) REFERENCES assessments(id)
    );

    CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL,
        report_type TEXT NOT NULL,
        title TEXT NOT NULL,
        file_path TEXT,
        content_summary TEXT,
        generated_at TEXT,
        FOREIGN KEY(assessment_id) REFERENCES assessments(id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        user TEXT DEFAULT 'security_analyst',
        action TEXT NOT NULL,
        target TEXT,
        assessment_id TEXT,
        timestamp TEXT,
        result TEXT DEFAULT 'SUCCESS',
        details TEXT
    );
    """)
    conn.commit()
    conn.close()

class DatabaseSession:
    def __init__(self):
        self.conn = get_connection()

    def close(self):
        self.conn.close()

def get_db():
    db = DatabaseSession()
    try:
        yield db
    finally:
        db.close()
