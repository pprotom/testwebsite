export type AuditVerdict = 'PASS' | 'NOT PASS' | 'UNKNOWN';

export type CheckStatus = 'PASS' | 'FAIL' | 'UNKNOWN';

export type Severity = 'P0' | 'P1' | 'P2' | 'P3';

export interface P0Gate {
  id: number;
  name: string;
  thaiName: string;
  description: string;
  passed: boolean;
  status: CheckStatus;
  failedItem?: string;
  evidencePath?: string;
  severity: 'P0';
}

export interface ChecklistItem {
  id: string;
  module: 'recon' | 'files' | 'weblayer' | 'infra' | 'supply';
  check: string;
  status: CheckStatus;
  score: 0 | 1 | 2;
  evidence: string[];
  note: string;
  p0_gate_id?: number;
}

export interface SecurityFinding {
  title: string;
  severity: Severity;
  affected: string;
  evidence: string[];
  reproduce: string;
  impact: string;
  remediation: string;
  cve?: string;
  cvss?: number;
  owasp_code?: string; // e.g. 'A05:2021'
}

export interface OWASPRiskCategory {
  code: string; // e.g. 'A01:2021'
  title: string;
  thaiTitle: string;
  status: CheckStatus;
  relatedChecks: string[];
  p0GateIds?: number[];
  description: string;
  impact: string;
  remediationSummary: string;
}

export type TargetEnvironment = 'production' | 'staging' | 'development';

export interface ProductionAuditSettings {
  environment: TargetEnvironment;
  rate_limit_rps: number; // requests per second (e.g. 1, 2, 5, 10)
  read_only_mode: boolean; // safe read-only methods only (GET/HEAD/OPTIONS)
  excluded_paths: string[]; // critical endpoints blacklisted from probing
  custom_audit_header: string; // e.g. X-Security-Audit: Authorized-Production-Audit
  maintenance_window_tag: string; // e.g. "Off-Peak Window (00:00 - 05:00)"
  waf_bypass_token?: string; // optional SOC/WAF authorization token
}

export interface AuditReport {
  id: string;
  target_url: string;
  domain: string;
  ip?: string;
  date: string;
  verdict: AuditVerdict;
  coverage_pct: number;
  safe_mode: boolean;
  target_environment?: TargetEnvironment;
  production_settings?: ProductionAuditSettings;
  summary: {
    pass: number;
    fail: number;
    unknown: number;
    total: number;
  };
  p0_gates: P0Gate[];
  items: ChecklistItem[];
  findings: SecurityFinding[];
  owasp_matrix?: OWASPRiskCategory[];
  limitations: string[];
  commands_run: string[];
  duration_seconds: number;
  evidence_count: number;
}

export interface DeltaComparison {
  baseline_date: string;
  current_date: string;
  status: 'IMPROVED' | 'REGRESSED' | 'NEUTRAL';
  score_diff: number;
  coverage_diff: number;
  new_failures: string[];
  fixed_issues: string[];
  unchanged_issues: string[];
}

export interface AuditConfigInput {
  url: string;
  domain: string;
  allowed_domains: string[];
  safe_mode: boolean;
  allow_risky: string[];
  confirm_large_port_scan: boolean;
  selected_module?: 'all' | 'recon' | 'files' | 'weblayer' | 'infra' | 'supply';
  environment: TargetEnvironment;
  production_settings: ProductionAuditSettings;
}
