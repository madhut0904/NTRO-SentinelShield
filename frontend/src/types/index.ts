export interface Target {
  id: string;
  name: string;
  repo_path?: string;
  docker_compose_path?: string;
  branch: string;
  environment: string;
  target_url: string;
  is_approved_sandbox: boolean;
  safety_status: 'GREEN' | 'RED';
  description?: string;
  created_at: string;
}

export interface EvidenceItem {
  id: string;
  evidence_code: string;
  finding_id: string;
  timestamp: string;
  test_identity: string;
  request_data: Record<string, any>;
  response_data: Record<string, any>;
  source_file?: string;
  code_line?: number;
  log_snippet?: string;
  sha256_hash: string;
}

export interface PoCTest {
  id: string;
  finding_id: string;
  title: string;
  purpose: string;
  target_url: string;
  method: string;
  test_identity: string;
  headers: Record<string, any>;
  payload: Record<string, any>;
  expected_result: string;
  actual_result?: string;
  status: 'READY' | 'PROVEN' | 'FAILED' | 'BLOCKED';
  is_safe: boolean;
  executed_at?: string;
}

export interface Remediation {
  id: string;
  finding_id: string;
  problem: string;
  root_cause: string;
  recommended_fix: string;
  safe_patch_diff: string;
  security_impact: string;
  applied_to_sandbox: boolean;
  applied_at?: string;
  created_at: string;
}

export interface Retest {
  id: string;
  finding_id: string;
  before_status_code: number;
  before_response?: string;
  after_status_code: number;
  after_response?: string;
  result: 'FIXED' | 'STILL_VULNERABLE' | 'REGRESSION';
  verified_status: string;
  retest_timestamp: string;
  execution_notes?: string;
}

export interface Finding {
  id: string;
  finding_code: string;
  assessment_id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cvss_score: number;
  cvss_vector?: string;
  cwe: string;
  file_path?: string;
  line_number?: number;
  code_snippet?: string;
  description: string;
  status: 'OPEN' | 'VALIDATED' | 'FIXED' | 'REGRESSION' | 'FALSE_POSITIVE';
  confidence: 'LOW' | 'MEDIUM' | 'HIGH' | 'VALIDATED';
  is_correlated: boolean;
  static_evidence: Record<string, any>;
  runtime_evidence: Record<string, any>;
  api_evidence: Record<string, any>;
  auth_context: Record<string, any>;
  created_at: string;
  updated_at: string;
  evidences?: EvidenceItem[];
  poc?: PoCTest;
  remediation?: Remediation;
  retests?: Retest[];
}

export interface SecurityControl {
  id: string;
  assessment_id: string;
  control_id: string;
  name: string;
  category: string;
  expected: string;
  tested: boolean;
  result: 'PASS' | 'FAIL' | 'WARN' | 'NOT_TESTED';
  evidence_id?: string;
  confidence: string;
  description?: string;
}

export interface Endpoint {
  id: string;
  assessment_id: string;
  method: string;
  path: string;
  auth_required: boolean;
  auth_mechanism: string;
  parameters: any[];
  sensitive_fields: any[];
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  discovered_via: string;
}

export interface Assessment {
  id: string;
  target_id: string;
  title: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  assurance_score: number;
  score_breakdown: Record<string, number>;
  summary?: string;
  created_at: string;
  completed_at?: string;
  target?: Target;
  findings?: Finding[];
  controls?: SecurityControl[];
}

export interface DashboardStats {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  validated_findings: number;
  false_positives: number;
  fixed_findings: number;
  regression_findings: number;
  security_controls_tested: number;
  tests_passed: number;
  tests_failed: number;
  assurance_score: number;
  score_breakdown: Record<string, number>;
  category_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  posture_trend: Array<{ scan: string; score: number; findings: number }>;
}

export interface ReportItem {
  id: string;
  assessment_id: string;
  report_type: 'PDF' | 'HTML' | 'JSON';
  title: string;
  file_path?: string;
  content_summary?: string;
  generated_at: string;
}
