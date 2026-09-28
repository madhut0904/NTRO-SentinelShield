import { Target, Assessment, Finding, SecurityControl, DashboardStats, ReportItem } from '../types';

const API_BASE = (import.meta.env.VITE_API_BASE as string) || '/api';

export const api = {
  // Targets
  async getTargets(): Promise<Target[]> {
    try {
      const res = await fetch(`${API_BASE}/targets`);
      if (res.ok) return await res.json();
    } catch {}
    return [
      {
        id: 'tgt-sandbox-01',
        name: 'World Monitor Sandbox',
        repo_path: './sandbox/worldmonitor',
        docker_compose_path: './sandbox/docker-compose.yml',
        branch: 'main',
        environment: 'SANDBOX',
        target_url: 'http://localhost:8080',
        is_approved_sandbox: true,
        safety_status: 'GREEN',
        description: 'Isolated Docker digital twin sandbox container.',
        created_at: new Date().toISOString()
      }
    ];
  },

  async createTarget(data: Partial<Target>): Promise<Target> {
    const res = await fetch(`${API_BASE}/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to register target');
    }
    return await res.json();
  },

  // Assessments
  async getAssessments(): Promise<Assessment[]> {
    try {
      const res = await fetch(`${API_BASE}/assessments`);
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  async getAssessment(id: string): Promise<Assessment> {
    const res = await fetch(`${API_BASE}/assessments/${id}`);
    if (!res.ok) throw new Error('Assessment not found');
    return await res.json();
  },

  async createAssessment(targetId: string, title: string): Promise<Assessment> {
    const res = await fetch(`${API_BASE}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_id: targetId, title })
    });
    if (!res.ok) throw new Error('Failed to run assessment');
    return await res.json();
  },

  // Findings
  async getFindings(): Promise<Finding[]> {
    try {
      const res = await fetch(`${API_BASE}/findings`);
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  async getFinding(id: string): Promise<Finding> {
    const res = await fetch(`${API_BASE}/findings/${id}`);
    if (!res.ok) throw new Error('Finding not found');
    return await res.json();
  },

  // Safe PoC Runner
  async executePoC(findingId: string) {
    const res = await fetch(`${API_BASE}/poc/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_id: findingId })
    });
    return await res.json();
  },

  // Remediation
  async applyRemediation(findingId: string) {
    const res = await fetch(`${API_BASE}/remediation/${findingId}/apply`, {
      method: 'POST'
    });
    return await res.json();
  },

  // Retest
  async executeRetest(findingId: string) {
    const res = await fetch(`${API_BASE}/retest/${findingId}`, {
      method: 'POST'
    });
    return await res.json();
  },

  // Security Controls
  async getSecurityControls(): Promise<SecurityControl[]> {
    try {
      const res = await fetch(`${API_BASE}/security-controls`);
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  // Attack Surface
  async getAttackSurface(assessmentId: string) {
    try {
      const res = await fetch(`${API_BASE}/attack-surface/${assessmentId}`);
      if (res.ok) return await res.json();
    } catch {}
    return {
      nodes: [
        { id: 'frontend', label: 'Web Frontend (Next.js)', type: 'layer', risk: 'LOW' },
        { id: 'api_gateway', label: 'API Gateway & Router', type: 'layer', risk: 'MEDIUM' },
        { id: 'auth_service', label: 'Authentication & RBAC', type: 'control', risk: 'HIGH' },
        { id: 'dossier_service', label: 'Intel Dossiers API', type: 'endpoint', risk: 'CRITICAL' },
        { id: 'database', label: 'Database & Storage', type: 'storage', risk: 'LOW' }
      ],
      edges: [
        { from: 'frontend', to: 'api_gateway', relation: 'HTTPS / REST' },
        { from: 'api_gateway', to: 'auth_service', relation: 'JWT Validation' },
        { from: 'api_gateway', to: 'dossier_service', relation: 'Route Delegation' },
        { from: 'dossier_service', to: 'database', relation: 'Query' }
      ]
    };
  },

  // Reports
  async generateReport(assessmentId: string, reportType: 'PDF' | 'HTML' | 'JSON'): Promise<ReportItem> {
    const res = await fetch(`${API_BASE}/reports/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessment_id: assessmentId, report_type: reportType })
    });
    return await res.json();
  },

  // Dashboard Stats
  async getDashboardStats(): Promise<DashboardStats> {
    try {
      const res = await fetch(`${API_BASE}/dashboard`);
      if (res.ok) return await res.json();
    } catch {}
    return {
      total_findings: 4,
      critical: 1,
      high: 1,
      medium: 1,
      low: 1,
      validated_findings: 3,
      false_positives: 0,
      fixed_findings: 1,
      regression_findings: 0,
      security_controls_tested: 8,
      tests_passed: 5,
      tests_failed: 3,
      assurance_score: 82.0,
      score_breakdown: {
        Authentication: 88.0,
        Authorization: 65.0,
        'API Security': 80.0,
        'Input Validation': 85.0,
        Dependencies: 78.0,
        Configuration: 82.0,
        'Security Headers': 70.0,
        Secrets: 75.0
      },
      category_distribution: {
        'Broken Authorization': 1,
        'Security Headers': 1,
        Dependencies: 1,
        Secrets: 1
      },
      severity_distribution: {
        CRITICAL: 1,
        HIGH: 1,
        MEDIUM: 1,
        LOW: 1
      },
      posture_trend: [
        { scan: 'Day -4', score: 68, findings: 9 },
        { scan: 'Day -3', score: 72, findings: 7 },
        { scan: 'Day -2', score: 77, findings: 5 },
        { scan: 'Day -1', score: 79, findings: 4 },
        { scan: 'Current', score: 82, findings: 4 }
      ]
    };
  },

  // Seed Demo State
  async seedDemo() {
    const res = await fetch(`${API_BASE}/demo/seed`, { method: 'POST' });
    return await res.json();
  }
};
