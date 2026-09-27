"use client";

import Link from "next/link";
import React, { useMemo, useState } from "react";
import type { Project, Scan, ToolName } from "@/lib/api";
import { groupScansIntoRuns, type ScanRun } from "@/lib/scanRuns";
import StatusDot from "@/components/StatusDot";
import EmptyState from "@/components/EmptyState";
import {
  ChevronDownIcon,
  ChevronRightIcon,
  TrashIcon,
  ZapIcon,
  ShieldIcon,
  CodeIcon,
  LayersIcon,
  SearchIcon,
  GlobeIcon,
  ActivityIcon,
} from "@/components/icons";

const TOOL_ICONS: Record<string, React.ReactNode> = {
  nuclei: <ZapIcon width={14} height={14} style={{ color: "#d29922" }} />,
  semgrep: <CodeIcon width={14} height={14} style={{ color: "#3fb950" }} />,
  trivy: <LayersIcon width={14} height={14} style={{ color: "#bc8cff" }} />,
  gitleaks: <ShieldIcon width={14} height={14} style={{ color: "#f85149" }} />,
  checkov: <ShieldIcon width={14} height={14} style={{ color: "#ff7b72" }} />,
  subfinder: <SearchIcon width={14} height={14} style={{ color: "#388bfd" }} />,
  httpx: <GlobeIcon width={14} height={14} style={{ color: "#58a6ff" }} />,
};

function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  const hours = Math.floor(diff / 3_600_000);
  const days = Math.floor(diff / 86_400_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function formatDuration(start: string | null, end: string | null): string {
  if (!start) return "—";
  const endMs = end ? new Date(end).getTime() : Date.now();
  const secs = Math.max(0, Math.round((endMs - new Date(start).getTime()) / 1000));
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}m ${s}s`;
}

interface ScanRunsTableProps {
  scans: Scan[];
  onDeleteScan: (scan: Scan) => void;
  showProjectName?: boolean;
  projectMap?: Map<string, Project>;
}

export default function ScanRunsTable({
  scans,
  onDeleteScan,
  showProjectName = false,
  projectMap,
}: ScanRunsTableProps) {
  const [viewMode, setViewMode] = useState<"grouped" | "flat">("grouped");
  const [expandedRunIds, setExpandedRunIds] = useState<Set<string>>(new Set());

  // Local filters
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [toolFilter, setToolFilter] = useState<string>("");
  const [query, setQuery] = useState<string>("");

  // Group into runs
  const runs = useMemo(() => groupScansIntoRuns(scans), [scans]);

  // Extract available tools for filtering
  const availableTools = useMemo(() => {
    const set = new Set<ToolName>();
    for (const s of scans) {
      if (s.tool) set.add(s.tool);
    }
    return Array.from(set).sort();
  }, [scans]);

  // Filtered runs
  const filteredRuns = useMemo(() => {
    return runs.filter((run) => {
      if (statusFilter && run.status !== statusFilter) return false;

      if (toolFilter) {
        if (toolFilter === "pipeline") {
          if (run.type !== "codebase_pipeline" && run.type !== "recon_pipeline") return false;
        } else {
          const hasTool = run.scans.some((s) => s.tool === toolFilter);
          if (!hasTool) return false;
        }
      }

      if (query.trim()) {
        const q = query.toLowerCase();
        const targetVal = run.target.value.toLowerCase();
        const runTitle = run.title.toLowerCase();
        const runId = run.id.toLowerCase();
        const projectName = showProjectName && projectMap ? (projectMap.get(run.projectId)?.name ?? "").toLowerCase() : "";

        const matches =
          targetVal.includes(q) ||
          runTitle.includes(q) ||
          runId.includes(q) ||
          projectName.includes(q) ||
          run.scans.some((s) => s.tool.toLowerCase().includes(q) || s.id.toLowerCase().includes(q));

        if (!matches) return false;
      }

      return true;
    });
  }, [runs, statusFilter, toolFilter, query, showProjectName, projectMap]);

  // Filtered flat scans
  const filteredScans = useMemo(() => {
    return scans.filter((scan) => {
      if (statusFilter && scan.status !== statusFilter) return false;
      if (toolFilter && toolFilter !== "pipeline" && scan.tool !== toolFilter) return false;

      if (query.trim()) {
        const q = query.toLowerCase();
        const targetVal = scan.target.value.toLowerCase();
        const toolName = scan.tool.toLowerCase();
        const scanId = scan.id.toLowerCase();
        const projectName = showProjectName && projectMap ? (projectMap.get(scan.project_id)?.name ?? "").toLowerCase() : "";

        const matches =
          targetVal.includes(q) ||
          toolName.includes(q) ||
          scanId.includes(q) ||
          projectName.includes(q);

        if (!matches) return false;
      }

      return true;
    });
  }, [scans, statusFilter, toolFilter, query, showProjectName, projectMap]);

  function toggleExpand(runId: string) {
    setExpandedRunIds((prev) => {
      const next = new Set(prev);
      if (next.has(runId)) {
        next.delete(runId);
      } else {
        next.add(runId);
      }
      return next;
    });
  }

  function toggleExpandAll() {
    if (expandedRunIds.size === filteredRuns.length) {
      setExpandedRunIds(new Set());
    } else {
      setExpandedRunIds(new Set(filteredRuns.map((r) => r.id)));
    }
  }

  const allExpanded = filteredRuns.length > 0 && expandedRunIds.size === filteredRuns.length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {/* ── Table Toolbar & Filters ────────────────────────────────────── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: 10,
          padding: "12px 16px",
          background: "var(--bg-subtle)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        {/* Left: Search & Filter selects */}
        <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 8, flex: 1 }}>
          <div style={{ position: "relative", minWidth: 180, maxWidth: 260 }}>
            <SearchIcon
              width={13}
              height={13}
              style={{
                position: "absolute",
                left: 9,
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--text-subtle)",
                pointerEvents: "none",
              }}
            />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter scans or targets…"
              style={{ paddingLeft: 28, fontSize: 12, height: 30, width: "100%" }}
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{ fontSize: 12, height: 30, padding: "0 8px" }}
          >
            <option value="">All Statuses</option>
            <option value="running">Running</option>
            <option value="queued">Queued</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>

          <select
            value={toolFilter}
            onChange={(e) => setToolFilter(e.target.value)}
            style={{ fontSize: 12, height: 30, padding: "0 8px" }}
          >
            <option value="">All Engines</option>
            <option value="pipeline">⚡ Pipelines Only</option>
            {availableTools.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>

        {/* Right: View Mode Toggle & Expand All */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {viewMode === "grouped" && filteredRuns.length > 0 && (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={toggleExpandAll}
              style={{ fontSize: 11, padding: "3px 8px" }}
            >
              {allExpanded ? "Collapse all" : "Expand all"}
            </button>
          )}

          <div
            style={{
              display: "flex",
              background: "var(--panel)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              padding: 2,
            }}
          >
            <button
              type="button"
              className={`btn btn-sm ${viewMode === "grouped" ? "btn-secondary" : "btn-ghost"}`}
              onClick={() => setViewMode("grouped")}
              style={{ fontSize: 11, padding: "2px 8px", height: 24 }}
            >
              Grouped Runs ({runs.length})
            </button>
            <button
              type="button"
              className={`btn btn-sm ${viewMode === "flat" ? "btn-secondary" : "btn-ghost"}`}
              onClick={() => setViewMode("flat")}
              style={{ fontSize: 11, padding: "2px 8px", height: 24 }}
            >
              Flat List ({scans.length})
            </button>
          </div>
        </div>
      </div>

      {/* ── Grouped Runs View ─────────────────────────────────────────── */}
      {viewMode === "grouped" ? (
        filteredRuns.length === 0 ? (
          <div style={{ padding: 32 }}>
            <EmptyState
              icon={<ActivityIcon />}
              title="No scan runs found"
              description="No audit sessions match the selected filter criteria."
            />
          </div>
        ) : (
          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 34 }}></th>
                  <th>Run / Session</th>
                  {showProjectName && <th>Project</th>}
                  <th>Target</th>
                  <th>Findings</th>
                  <th>Engines</th>
                  <th>Duration</th>
                  <th>Started</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRuns.map((run) => {
                  const isExpanded = expandedRunIds.has(run.id);
                  const isPipeline = run.type === "codebase_pipeline" || run.type === "recon_pipeline";
                  const critCount = run.bySeverity["critical"] ?? 0;
                  const highCount = run.bySeverity["high"] ?? 0;

                  return (
                    <React.Fragment key={run.id}>
                      {/* Parent Run Row */}
                      <tr
                        className="clickable"
                        onClick={() => toggleExpand(run.id)}
                        style={{
                          background: isExpanded ? "rgba(56, 139, 253, 0.04)" : undefined,
                          fontWeight: 500,
                        }}
                      >
                        <td style={{ textAlign: "center", color: "var(--text-muted)", padding: "8px 4px" }}>
                          {run.scans.length > 1 ? (
                            isExpanded ? (
                              <ChevronDownIcon width={14} height={14} />
                            ) : (
                              <ChevronRightIcon width={14} height={14} />
                            )
                          ) : (
                            <span style={{ fontSize: 10, color: "var(--text-subtle)" }}>•</span>
                          )}
                        </td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <StatusDot status={run.status} />
                            <div>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <span style={{ fontWeight: 600, color: "var(--text)" }}>{run.title}</span>
                                {isPipeline && (
                                  <span
                                    style={{
                                      fontSize: 9.5,
                                      fontWeight: 700,
                                      textTransform: "uppercase",
                                      padding: "1px 5px",
                                      borderRadius: 4,
                                      background: "rgba(56, 139, 253, 0.12)",
                                      color: "var(--accent)",
                                      border: "1px solid rgba(56, 139, 253, 0.25)",
                                    }}
                                  >
                                    PIPELINE
                                  </span>
                                )}
                              </div>
                              <span className="muted" style={{ fontSize: 10.5, fontFamily: "JetBrains Mono, monospace" }}>
                                {run.id.slice(0, 8)}
                              </span>
                            </div>
                          </div>
                        </td>
                        {showProjectName && (
                          <td>
                            <span style={{ fontWeight: 600, fontSize: 12 }}>
                              {projectMap?.get(run.projectId)?.name ?? "—"}
                            </span>
                          </td>
                        )}
                        <td>
                          <code style={{ fontSize: 11.5 }}>{run.target.value}</code>
                        </td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                            <span style={{ fontWeight: 700 }}>{run.totalFindings}</span>
                            {critCount > 0 && (
                              <span className="badge critical" style={{ fontSize: 9.5, padding: "0 4px" }}>
                                {critCount} crit
                              </span>
                            )}
                            {highCount > 0 && (
                              <span className="badge high" style={{ fontSize: 9.5, padding: "0 4px" }}>
                                {highCount} high
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                            {run.scans.map((s) => (
                              <span
                                key={s.id}
                                style={{
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: 3,
                                  fontSize: 10.5,
                                  padding: "1px 5px",
                                  borderRadius: 4,
                                  background: "var(--bg-subtle)",
                                  border: "1px solid var(--border)",
                                }}
                              >
                                {TOOL_ICONS[s.tool]}
                                <span>{s.tool}</span>
                              </span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <span className="muted" style={{ fontSize: 11.5 }}>
                            {formatDuration(run.startedAt, run.finishedAt)}
                          </span>
                        </td>
                        <td>
                          <span className="muted" style={{ fontSize: 11.5 }} title={new Date(run.createdAt).toLocaleString()}>
                            {relativeTime(run.createdAt)}
                          </span>
                        </td>
                        <td onClick={(e) => e.stopPropagation()} style={{ textAlign: "right" }}>
                          {run.scans.length === 1 ? (
                            <Link href={`/scans/${run.scans[0].id}`} className="btn btn-ghost btn-sm" style={{ fontSize: 11 }}>
                              Details →
                            </Link>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              onClick={() => toggleExpand(run.id)}
                              style={{ fontSize: 11 }}
                            >
                              {isExpanded ? "Hide engines ▲" : `View ${run.scans.length} engines ▼`}
                            </button>
                          )}
                        </td>
                      </tr>

                      {/* Expanded Child Engine Rows */}
                      {isExpanded &&
                        run.scans.map((subScan) => (
                          <tr
                            key={subScan.id}
                            style={{
                              background: "rgba(0, 0, 0, 0.15)",
                              borderLeft: "3px solid var(--accent)",
                            }}
                          >
                            <td></td>
                            <td style={{ paddingLeft: 24 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <span style={{ display: "flex", alignItems: "center" }}>
                                  {TOOL_ICONS[subScan.tool]}
                                </span>
                                <span style={{ fontWeight: 600, fontSize: 12 }}>{subScan.tool}</span>
                                <span className={`badge ${subScan.status}`} style={{ fontSize: 10, padding: "0 5px" }}>
                                  {subScan.status}
                                </span>
                              </div>
                            </td>
                            {showProjectName && <td></td>}
                            <td>
                              <code style={{ fontSize: 11, color: "var(--text-muted)" }}>
                                {subScan.target.value}
                              </code>
                            </td>
                            <td>
                              <span style={{ fontSize: 12, fontWeight: 600 }}>
                                {subScan.stats?.findings != null ? subScan.stats.findings : "—"}
                              </span>
                            </td>
                            <td className="muted" style={{ fontSize: 11 }}>
                              Engine scan
                            </td>
                            <td>
                              <span className="muted" style={{ fontSize: 11 }}>
                                {formatDuration(subScan.started_at, subScan.finished_at)}
                              </span>
                            </td>
                            <td>
                              <span className="muted" style={{ fontSize: 11 }}>
                                {relativeTime(subScan.started_at ?? subScan.created_at)}
                              </span>
                            </td>
                            <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                              <Link
                                href={`/scans/${subScan.id}`}
                                className="btn btn-ghost btn-sm"
                                style={{ fontSize: 11, marginRight: 4 }}
                              >
                                Details →
                              </Link>
                              <button
                                type="button"
                                className="btn btn-ghost btn-sm"
                                title="Delete engine scan"
                                onClick={() => onDeleteScan(subScan)}
                                style={{ color: "var(--danger)", padding: "3px 6px" }}
                              >
                                <TrashIcon width={12} height={12} />
                              </button>
                            </td>
                          </tr>
                        ))}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )
      ) : (
        /* ── Flat List View ──────────────────────────────────────────── */
        filteredScans.length === 0 ? (
          <div style={{ padding: 32 }}>
            <EmptyState
              icon={<ActivityIcon />}
              title="No scans found"
              description="No individual scans match the selected filter criteria."
            />
          </div>
        ) : (
          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Tool</th>
                  {showProjectName && <th>Project</th>}
                  <th>Target</th>
                  <th>Findings</th>
                  <th>Duration</th>
                  <th>Started</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="clickable"
                    onClick={() => {
                      window.location.href = `/scans/${scan.id}`;
                    }}
                  >
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <StatusDot status={scan.status} />
                        <span className={`badge ${scan.status}`}>{scan.status}</span>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        {TOOL_ICONS[scan.tool]}
                        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, fontWeight: 600 }}>
                          {scan.tool}
                        </span>
                      </div>
                    </td>
                    {showProjectName && (
                      <td>
                        <span style={{ fontWeight: 600, fontSize: 12 }}>
                          {projectMap?.get(scan.project_id)?.name ?? "—"}
                        </span>
                      </td>
                    )}
                    <td>
                      <code style={{ fontSize: 12 }}>{scan.target.value}</code>
                    </td>
                    <td>
                      {scan.stats?.findings != null ? (
                        <span style={{ fontWeight: 600 }}>
                          {scan.stats.findings}
                          {(scan.stats.by_severity?.["critical"] ?? 0) > 0 && (
                            <span className="badge critical" style={{ fontSize: 10, padding: "0 4px", marginLeft: 6 }}>
                              {scan.stats.by_severity?.["critical"]} crit
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>
                      <span className="muted" style={{ fontSize: 12 }}>
                        {formatDuration(scan.started_at, scan.finished_at)}
                      </span>
                    </td>
                    <td>
                      <span className="muted" style={{ fontSize: 12 }} title={new Date(scan.started_at ?? scan.created_at).toLocaleString()}>
                        {relativeTime(scan.started_at ?? scan.created_at)}
                      </span>
                    </td>
                    <td onClick={(e) => e.stopPropagation()} style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <Link href={`/scans/${scan.id}`} className="btn btn-ghost btn-sm" style={{ marginRight: 4 }}>
                        Details →
                      </Link>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        title="Delete scan"
                        onClick={() => onDeleteScan(scan)}
                        style={{ color: "var(--danger)", padding: "4px 8px" }}
                      >
                        <TrashIcon width={13} height={13} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  );
}
