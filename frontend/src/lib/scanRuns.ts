import type { Scan, ScanStatus, TargetKind } from "@/lib/api";

export type ScanRunType = "codebase_pipeline" | "recon_pipeline" | "suite" | "single";

export type ScanRun = {
  id: string;
  type: ScanRunType;
  title: string;
  projectId: string;
  target: { kind: TargetKind; value: string };
  status: ScanStatus;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
  totalFindings: number;
  bySeverity: Record<string, number>;
  scans: Scan[];
};

export function deriveRunStatus(scans: Scan[]): ScanStatus {
  if (scans.some((s) => s.status === "running")) return "running";
  if (scans.some((s) => s.status === "queued")) return "queued";
  if (scans.some((s) => s.status === "pending")) return "pending";
  if (scans.every((s) => s.status === "completed")) return "completed";
  if (scans.some((s) => s.status === "failed")) return "failed";
  if (scans.every((s) => s.status === "cancelled")) return "cancelled";
  return "completed";
}

export function groupScansIntoRuns(scans: Scan[]): ScanRun[] {
  const runsMap = new Map<string, Scan[]>();
  const singleScans: Scan[] = [];

  for (const scan of scans) {
    const taskId = scan.task_id ?? "";
    // Check for pipeline ID prefix format (e.g. uuid-tool)
    const pipelineMatch = taskId.match(
      /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-(gitleaks|semgrep|trivy|checkov|subfinder|httpx|nuclei)/i
    );

    if (pipelineMatch) {
      const pipelineId = pipelineMatch[1];
      const existing = runsMap.get(pipelineId) ?? [];
      existing.push(scan);
      runsMap.set(pipelineId, existing);
    } else {
      singleScans.push(scan);
    }
  }

  const result: ScanRun[] = [];

  // 1. Process pipeline runs
  for (const [pipelineId, runScans] of runsMap.entries()) {
    // Sort child scans chronologically
    runScans.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

    const first = runScans[0];
    const tools = runScans.map((s) => s.tool);
    const isRecon = tools.some((t) => t === "subfinder" || t === "httpx" || t === "nuclei");

    const runType: ScanRunType = isRecon ? "recon_pipeline" : "codebase_pipeline";
    const title = isRecon
      ? `Recon & DAST Pipeline (${runScans.length} stages)`
      : `Full Codebase Audit (${runScans.length} engines)`;

    const totalFindings = runScans.reduce((sum, s) => sum + (s.stats?.findings ?? 0), 0);
    const bySeverity: Record<string, number> = {};
    for (const s of runScans) {
      if (s.stats?.by_severity) {
        for (const [k, v] of Object.entries(s.stats.by_severity)) {
          bySeverity[k] = (bySeverity[k] ?? 0) + Number(v);
        }
      }
    }

    const startTimes = runScans.map((s) => s.started_at).filter(Boolean) as string[];
    const finishTimes = runScans.map((s) => s.finished_at).filter(Boolean) as string[];

    const startedAt = startTimes.length > 0 ? startTimes.sort()[0] : first.started_at;
    const finishedAt =
      finishTimes.length === runScans.length ? finishTimes.sort()[finishTimes.length - 1] : null;

    result.push({
      id: pipelineId,
      type: runType,
      title,
      projectId: first.project_id,
      target: first.target,
      status: deriveRunStatus(runScans),
      startedAt,
      finishedAt,
      createdAt: first.created_at,
      totalFindings,
      bySeverity,
      scans: runScans,
    });
  }

  // 2. Process batch / standalone single scans
  // Check if any single scans were created at the same second for the same target (batch suite)
  const batchMap = new Map<string, Scan[]>();
  const leftovers: Scan[] = [];

  for (const scan of singleScans) {
    const timeKey = scan.created_at.slice(0, 19); // second precision
    const key = `${scan.project_id}_${scan.target.value}_${timeKey}`;
    const group = batchMap.get(key) ?? [];
    group.push(scan);
    batchMap.set(key, group);
  }

  for (const [key, group] of batchMap.entries()) {
    if (group.length > 1) {
      const first = group[0];
      const totalFindings = group.reduce((sum, s) => sum + (s.stats?.findings ?? 0), 0);
      const bySeverity: Record<string, number> = {};
      for (const s of group) {
        if (s.stats?.by_severity) {
          for (const [k, v] of Object.entries(s.stats.by_severity)) {
            bySeverity[k] = (bySeverity[k] ?? 0) + Number(v);
          }
        }
      }

      result.push({
        id: `batch-${key}`,
        type: "suite",
        title: `Parallel Security Suite (${group.length} engines)`,
        projectId: first.project_id,
        target: first.target,
        status: deriveRunStatus(group),
        startedAt: group.map((s) => s.started_at).filter(Boolean)[0] ?? first.started_at,
        finishedAt:
          group.every((s) => s.finished_at)
            ? group.map((s) => s.finished_at).sort()[group.length - 1]
            : null,
        createdAt: first.created_at,
        totalFindings,
        bySeverity,
        scans: group,
      });
    } else {
      leftovers.push(group[0]);
    }
  }

  // 3. Individual standalone scans
  for (const scan of leftovers) {
    result.push({
      id: scan.id,
      type: "single",
      title: `${scan.tool.toUpperCase()} Scan`,
      projectId: scan.project_id,
      target: scan.target,
      status: scan.status,
      startedAt: scan.started_at,
      finishedAt: scan.finished_at,
      createdAt: scan.created_at,
      totalFindings: scan.stats?.findings ?? 0,
      bySeverity: scan.stats?.by_severity ?? {},
      scans: [scan],
    });
  }

  // Sort runs newest first
  result.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  return result;
}
