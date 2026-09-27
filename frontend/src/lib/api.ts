const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const V1 = `${API_BASE}/api/v1`;

export type TargetKind = "domain" | "ip" | "cidr" | "url" | "path";
export type ToolName = "nuclei" | "subfinder" | "semgrep" | "trivy" | "gitleaks" | "checkov" | "httpx";
export type ScanStatus = "pending" | "queued" | "running" | "completed" | "failed" | "cancelled";
export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export type Project = {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
};

export type Target = {
  id: string;
  kind: TargetKind;
  value: string;
  is_active: boolean;
  created_at: string;
};

export type ScanStats = {
  lines: number;
  findings: number;
  by_severity: Record<string, number>;
};

export type Scan = {
  id: string;
  project_id: string;
  target_id: string | null;
  tool: ToolName;
  status: ScanStatus;
  target: { kind: TargetKind; value: string };
  config: Record<string, unknown>;
  task_id: string | null;
  stats: ScanStats | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
};

export type Finding = {
  id?: string;
  severity: Severity;
  template_id: string;
  name: string;
  matched_at: string;
  host: string;
  extracted: string[] | null;
  first_seen_at: string;
  last_seen_at: string;
};

export type ScanDiffSummary = {
  new_count: number;
  fixed_count: number;
  unchanged_count: number;
  current_total: number;
  previous_total: number;
};

export type ScanDiff = {
  base_scan_id: string;
  target_scan_id: string | null;
  summary: ScanDiffSummary;
  new_findings: Finding[];
  fixed_findings: Finding[];
  unchanged_findings: Finding[];
};

export type ScanResult = {
  id: number;
  tool: string;
  raw: Record<string, unknown>;
  created_at: string;
};

export type NucleiScanConfig = {
  severity?: string[];
  tags?: string[];
  exclude_tags?: string[];
  template_ids?: string[];
  exclude_template_ids?: string[];
  custom_headers?: string[];
  stop_at_first_match?: boolean;
  restrict_local_network?: boolean;
  rate_limit?: number;
  concurrency?: number;
  timeout?: number;
};

export type SubfinderScanConfig = {
  sources?: string[];
  exclude_sources?: string[];
  all_sources?: boolean;
  recursive?: boolean;
  rate_limit?: number;
  timeout?: number;
  max_time?: number;
  exclude_ip?: boolean;
};

export type SemgrepScanConfig = {
  config?: string;
};

export type TrivyScanConfig = {
  scanners?: string[];
  skip_db_update?: boolean;
  offline_scan?: boolean;
};

export type GitleaksScanConfig = {
  no_git?: boolean;
  redact?: boolean;
};

export type CheckovScanConfig = {
  framework?: string;
  skip_path?: string[];
};

export type HttpxScanConfig = {
  tech_detect?: boolean;
  follow_redirects?: boolean;
  ports?: (number | string)[];
  path?: string;
  threads?: number;
  rate_limit?: number;
  timeout?: number;
};

export type StartScanPayload = {
  tool: ToolName;
  target_id?: string;
  target?: { kind: TargetKind; value: string };
  config?:
    | NucleiScanConfig
    | SubfinderScanConfig
    | SemgrepScanConfig
    | TrivyScanConfig
    | GitleaksScanConfig
    | CheckovScanConfig
    | HttpxScanConfig;
};

export type WorkspaceEntry = {
  name: string;
  path: string;
  full_path: string;
};

export type WorkspaceResponse = {
  root: string;
  available: boolean;
  entries: WorkspaceEntry[];
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${V1}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (body?.detail) detail = String(body.detail);
    } catch {
      // keep status text
    }
    throw new Error(detail);
  }
  if (response.status === 204) {
    return undefined as unknown as T;
  }
  return (await response.json()) as T;
}

const ACTIVE_STATUSES: ScanStatus[] = ["pending", "queued", "running"];

export type CategoryScore = {
  category: string;
  score: number;
  grade: string;
  total_findings: number;
  counts_by_severity: Record<string, number>;
};

export type SecurityScore = {
  score: number;
  grade: string;
  total_findings: number;
  penalties: number;
  counts_by_severity: Record<string, number>;
  categories: Record<string, CategoryScore>;
};

export type OverviewRow = {
  project_name: string;
  total_findings: number;
  counts_by_severity: Record<string, number>;
  security_score: number;
  grade: string;
};

export type OverviewData = {
  title: string;
  generated_at: string;
  projects_reported: number;
  rows: OverviewRow[];
};

export type ReconPipelinePayload = {
  target_id?: string;
  target?: { kind: TargetKind; value: string };
  nuclei_severity?: Severity[];
};

export type ReconPipelineResponse = {
  pipeline_id: string;
  project_id: string;
  target: { kind: TargetKind; value: string };
  status: string;
  message: string;
};

export type CodebasePipelinePayload = {
  target_id?: string;
  target?: { kind: TargetKind; value: string };
  tools?: string[];
};

export type CodebasePipelineResponse = {
  pipeline_id: string;
  project_id: string;
  target: { kind: TargetKind; value: string };
  status: string;
  message: string;
};

export const api = {
  listProjects: () => request<Project[]>("/projects"),
  createProject: (payload: { name: string; description?: string }) =>
    request<Project>("/projects", { method: "POST", body: JSON.stringify(payload) }),
  getProject: (id: string) => request<Project>(`/projects/${id}`),
  deleteProject: (id: string) => request<void>(`/projects/${id}`, { method: "DELETE" }),
  listTargets: (projectId: string) => request<Target[]>(`/projects/${projectId}/targets`),
  addTarget: (projectId: string, payload: { kind: TargetKind; value: string }) =>
    request<Target>(`/projects/${projectId}/targets`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteTarget: (projectId: string, targetId: string) =>
    request<void>(`/projects/${projectId}/targets/${targetId}`, { method: "DELETE" }),
  listScans: (projectId: string) => request<Scan[]>(`/projects/${projectId}/scans`),
  listAllScans: (limit = 50) => request<Scan[]>(`/scans?limit=${limit}`),
  listRecentScans: (limit = 10) => request<Scan[]>(`/scans?limit=${limit}`),
  getActiveScanCount: async (): Promise<number> => {
    const scans = await request<Scan[]>(`/scans?limit=100`);
    return scans.filter((s) => ACTIVE_STATUSES.includes(s.status)).length;
  },
  startScan: (projectId: string, payload: StartScanPayload) =>
    request<Scan>(`/projects/${projectId}/scans`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  startBatchScans: (projectId: string, scans: StartScanPayload[]) =>
    request<Scan[]>(`/projects/${projectId}/scans/batch`, {
      method: "POST",
      body: JSON.stringify({ scans }),
    }),
  startReconPipeline: (projectId: string, payload: ReconPipelinePayload) =>
    request<ReconPipelineResponse>(`/projects/${projectId}/pipelines/recon`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  startCodebasePipeline: (projectId: string, payload: CodebasePipelinePayload) =>
    request<CodebasePipelineResponse>(`/projects/${projectId}/pipelines/codebase`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getProjectSecurityScore: (projectId: string) =>
    request<SecurityScore>(`/projects/${projectId}/security-score`),
  getScan: (id: string) => request<Scan>(`/scans/${id}`),
  deleteScan: (id: string) => request<void>(`/scans/${id}`, { method: "DELETE" }),
  cancelScan: (id: string) => request<Scan>(`/scans/${id}/cancel`, { method: "POST" }),
  listFindings: (id: string, severity?: string) =>
    request<Finding[]>(`/scans/${id}/findings${severity ? `?severity=${severity}` : ""}`),
  getScanDiff: (id: string, targetScanId?: string) =>
    request<ScanDiff>(`/scans/${id}/diff${targetScanId ? `?target_scan_id=${targetScanId}` : ""}`),
  getWorkspace: () => request<WorkspaceResponse>("/workspace"),
  listResults: (id: string) => request<ScanResult[]>(`/scans/${id}/results`),
  getOverview: () => request<OverviewData>("/reports/overview?format=json"),
};

export const TERMINAL_STATUSES: ScanStatus[] = ["completed", "failed", "cancelled"];

export function isTerminal(status: ScanStatus): boolean {
  return TERMINAL_STATUSES.includes(status);
}

export function overviewReportUrl(format: "pdf" | "html" = "pdf"): string {
  return `${V1}/reports/overview?format=${format}`;
}

export function formatDate(value: string | null): string {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}
