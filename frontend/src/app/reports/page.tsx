"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  overviewReportUrl,
  formatDate,
  type OverviewData,
  type OverviewRow,
  type Project,
  type Scan,
} from "@/lib/api";
import EmptyState from "@/components/EmptyState";
import KpiCard from "@/components/KpiCard";
import RiskBar from "@/components/RiskBar";
import StatusDot from "@/components/StatusDot";
import {
  FileIcon,
  FolderIcon,
  AlertTriangleIcon,
  CheckIcon,
  ExternalLinkIcon,
  ActivityIcon,
  ZapIcon,
} from "@/components/icons";

const SEVERITY_COLUMNS: { key: string; label: string; color: string }[] = [
  { key: "critical", label: "Critical", color: "var(--sev-critical)" },
  { key: "high", label: "High", color: "var(--sev-high)" },
  { key: "medium", label: "Medium", color: "var(--sev-medium)" },
  { key: "low", label: "Low", color: "var(--sev-low)" },
  { key: "info", label: "Info", color: "var(--sev-info)" },
];

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

export default function ReportsPage() {
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [overviewData, projectsData, scansData] = await Promise.all([
        api.getOverview().catch(() => null),
        api.listProjects().catch(() => []),
        api.listRecentScans(5).catch(() => []),
      ]);
      setOverview(overviewData);
      setProjects(projectsData);
      setRecentScans(scansData);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load report data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  // Project map for ID lookups
  const projectMap = useMemo(() => {
    const map = new Map<string, Project>();
    for (const p of projects) {
      map.set(p.name, p);
    }
    return map;
  }, [projects]);

  const rows = overview?.rows ?? [];

  // Identify unscanned projects
  const unscannedProjects = useMemo(() => {
    const scannedNames = new Set(rows.map((r) => r.project_name));
    return projects.filter((p) => !scannedNames.has(p.name));
  }, [projects, rows]);

  // Calculations derived directly from real OverviewRow data
  const totalFindings = useMemo(() => {
    return rows.reduce((sum, row) => sum + row.total_findings, 0);
  }, [rows]);

  const severityTotals = useMemo(() => {
    const totals: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const row of rows) {
      for (const key of Object.keys(totals)) {
        totals[key] += row.counts_by_severity?.[key] ?? 0;
      }
    }
    return totals;
  }, [rows]);

  // High risk projects needing immediate attention
  const attentionProjects = useMemo(() => {
    return rows.filter((r) => {
      const crit = r.counts_by_severity?.["critical"] ?? 0;
      const high = r.counts_by_severity?.["high"] ?? 0;
      return crit > 0 || high > 0;
    });
  }, [rows]);

  const hasData = rows.length > 0;
  const isZeroProjects = !loading && projects.length === 0;
  const isZeroScans = !loading && projects.length > 0 && rows.length === 0;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* ── Page Header ─────────────────────────────────────────────── */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div className="page-title-group">
          <h1>Security Reports</h1>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            Security posture and vulnerability overview across monitored projects
            {overview?.generated_at ? ` · Generated ${formatDate(overview.generated_at)}` : ""}
          </p>
        </div>

        {hasData && (
          <div style={{ display: "flex", gap: 8 }}>
            <a
              href={overviewReportUrl("pdf")}
              className="btn btn-primary btn-sm"
              style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 6 }}
            >
              <FileIcon width={13} height={13} />
              Download PDF
            </a>
            <a
              href={overviewReportUrl("html")}
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary btn-sm"
              style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 6 }}
            >
              <ExternalLinkIcon width={13} height={13} />
              View HTML
            </a>
          </div>
        )}
      </div>

      {/* ── Error Banner ────────────────────────────────────────────── */}
      {error && (
        <div className="error-banner">
          <AlertTriangleIcon width={16} height={16} />
          <span>{error}</span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => void loadData()}
            style={{ marginLeft: "auto", padding: "2px 6px" }}
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Initial Loading Skeleton ─────────────────────────────────── */}
      {loading && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14 }}>
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="card" style={{ padding: 18 }}>
                <div className="skeleton" style={{ height: 14, width: 80, marginBottom: 10, borderRadius: 4 }} />
                <div className="skeleton" style={{ height: 28, width: 60, borderRadius: 6 }} />
              </div>
            ))}
          </div>
          <div className="card" style={{ height: 200, padding: 24 }}>
            <div className="skeleton" style={{ height: 24, width: 160, marginBottom: 16, borderRadius: 4 }} />
            <div className="skeleton" style={{ height: 18, width: "100%", marginBottom: 8, borderRadius: 4 }} />
            <div className="skeleton" style={{ height: 18, width: "80%", borderRadius: 4 }} />
          </div>
        </div>
      )}

      {/* ── Empty States ────────────────────────────────────────────── */}
      {isZeroProjects && (
        <EmptyState
          icon={<FolderIcon />}
          title="No projects configured"
          description="Create a project and run security scans to generate executive security posture reports."
          action={{ label: "Go to Projects", href: "/projects" }}
        />
      )}

      {isZeroScans && (
        <EmptyState
          icon={<ActivityIcon />}
          title="No completed security audits yet"
          description="Projects have been registered, but no completed scans have generated findings yet."
          action={{ label: "Go to Projects", href: "/projects" }}
        />
      )}

      {/* ── Executive Summary KPI Cards ─────────────────────────────── */}
      {hasData && !loading && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14 }}>
          <KpiCard
            label="Audited Projects"
            value={`${rows.length} / ${projects.length || rows.length}`}
            sublabel={unscannedProjects.length > 0 ? `${unscannedProjects.length} projects unscanned` : "100% projects audited"}
            icon={<FolderIcon width={16} height={16} />}
            variant="default"
          />
          <KpiCard
            label="Total Findings"
            value={totalFindings}
            sublabel={`${severityTotals.medium} medium, ${severityTotals.low} low flaws`}
            icon={<FileIcon width={16} height={16} />}
            variant={totalFindings > 0 ? "warning" : "default"}
          />
          <KpiCard
            label="Critical Findings"
            value={severityTotals.critical}
            sublabel={severityTotals.critical > 0 ? "Requires urgent remediation" : "Zero critical vulnerabilities"}
            icon={<AlertTriangleIcon width={16} height={16} />}
            variant={severityTotals.critical > 0 ? "critical" : "success"}
          />
          <KpiCard
            label="High Severity"
            value={severityTotals.high}
            sublabel={severityTotals.high > 0 ? "Significant risk exposure" : "Zero high severity risks"}
            icon={<AlertTriangleIcon width={16} height={16} />}
            variant={severityTotals.high > 0 ? "high" : "default"}
          />
        </div>
      )}

      {/* ── Global Severity Distribution Card ────────────────────────── */}
      {hasData && !loading && (
        <div className="card" style={{ padding: "18px 20px" }}>
          <div className="card-header" style={{ marginBottom: 12 }}>
            <h2 style={{ margin: 0, fontSize: 14 }}>Global Vulnerability Distribution</h2>
          </div>

          <RiskBar counts={severityTotals} total={totalFindings} height={8} showLabels />

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
              gap: 12,
              marginTop: 16,
              paddingTop: 16,
              borderTop: "1px solid var(--border)",
            }}
          >
            {SEVERITY_COLUMNS.map((col) => {
              const count = severityTotals[col.key] ?? 0;
              const percent = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
              return (
                <div
                  key={col.key}
                  style={{
                    padding: "8px 12px",
                    borderRadius: "var(--radius-sm)",
                    background: "var(--bg-subtle)",
                    border: "1px solid var(--border)",
                  }}
                >
                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600 }}>
                    {col.label}
                  </div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: count > 0 ? col.color : "var(--text-subtle)", marginTop: 2 }}>
                    {count}
                    <span className="muted" style={{ fontSize: 11, fontWeight: 400, marginLeft: 6 }}>
                      ({percent}%)
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Attention Required Projects (Critical/High) ──────────────── */}
      {attentionProjects.length > 0 && !loading && (
        <div className="card" style={{ borderLeft: "3px solid var(--danger)", background: "rgba(248, 81, 73, 0.03)" }}>
          <div className="card-header" style={{ marginBottom: 12 }}>
            <h2 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0, fontSize: 14, color: "var(--danger)" }}>
              <AlertTriangleIcon width={16} height={16} />
              Attention Required — High Risk Projects ({attentionProjects.length})
            </h2>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
            {attentionProjects.map((row) => {
              const project = projectMap.get(row.project_name);
              const crit = row.counts_by_severity?.["critical"] ?? 0;
              const high = row.counts_by_severity?.["high"] ?? 0;

              return (
                <div
                  key={row.project_name}
                  style={{
                    padding: "12px 14px",
                    borderRadius: "var(--radius-md)",
                    background: "var(--panel)",
                    border: "1px solid var(--border)",
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontWeight: 600, fontSize: 13, color: "var(--text)" }}>{row.project_name}</span>
                    <div style={{ display: "flex", gap: 4 }}>
                      {crit > 0 && <span className="badge critical">{crit} crit</span>}
                      {high > 0 && <span className="badge high">{high} high</span>}
                    </div>
                  </div>

                  <RiskBar counts={row.counts_by_severity} total={row.total_findings} height={4} />

                  <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 2 }}>
                    {project ? (
                      <Link href={`/projects/${project.id}`} className="btn btn-ghost btn-sm" style={{ fontSize: 11, padding: "2px 6px" }}>
                        Inspect project →
                      </Link>
                    ) : (
                      <span className="muted" style={{ fontSize: 11 }}>{row.total_findings} findings</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Project Security Posture Table ───────────────────────────── */}
      {hasData && !loading && (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-header" style={{ padding: "18px 20px" }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 15 }}>Project Security Posture Matrix</h2>
              <p className="muted" style={{ margin: "2px 0 0", fontSize: 12 }}>
                Severity count breakdown per project based on latest scan execution
              </p>
            </div>
          </div>

          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Project Name</th>
                  <th style={{ textAlign: "center", width: 90 }}>Score / Grade</th>
                  <th style={{ width: 140 }}>Distribution</th>
                  <th style={{ textAlign: "right" }}>Total</th>
                  {SEVERITY_COLUMNS.map((col) => (
                    <th key={col.key} style={{ textAlign: "right" }}>
                      {col.label}
                    </th>
                  ))}
                  <th style={{ textAlign: "right" }}>Status</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const project = projectMap.get(row.project_name);
                  const crit = row.counts_by_severity?.["critical"] ?? 0;
                  const high = row.counts_by_severity?.["high"] ?? 0;
                  const med = row.counts_by_severity?.["medium"] ?? 0;
                  const score = row.security_score ?? 100;
                  const grade = row.grade ?? "A";
                  const gradeColor =
                    grade === "A"
                      ? "#3fb950"
                      : grade === "B"
                      ? "#58a6ff"
                      : grade === "C"
                      ? "#d29922"
                      : grade === "D"
                      ? "#db6d28"
                      : "#f85149";

                  // Deterministic status derived strictly from observed findings
                  let statusLabel = "Clean";
                  let statusBadge = "badge success";
                  if (crit > 0) {
                    statusLabel = "Critical Risk";
                    statusBadge = "badge critical";
                  } else if (high > 0) {
                    statusLabel = "High Risk";
                    statusBadge = "badge high";
                  } else if (med > 0) {
                    statusLabel = "Medium Risk";
                    statusBadge = "badge medium";
                  }

                  return (
                    <tr
                      key={row.project_name}
                      className={project ? "clickable" : undefined}
                      onClick={() => {
                        if (project) window.location.href = `/projects/${project.id}`;
                      }}
                    >
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <FolderIcon width={14} height={14} style={{ color: "var(--accent-hover)", flexShrink: 0 }} />
                          <span style={{ fontWeight: 600, color: "var(--text)" }}>{row.project_name}</span>
                        </div>
                      </td>
                      <td style={{ textAlign: "center" }}>
                        <div style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                          <span
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              justifyContent: "center",
                              width: 22,
                              height: 22,
                              borderRadius: 4,
                              background: `${gradeColor}22`,
                              color: gradeColor,
                              fontWeight: 700,
                              fontSize: 12,
                            }}
                          >
                            {grade}
                          </span>
                          <span style={{ fontWeight: 600, fontSize: 12 }}>{score}</span>
                        </div>
                      </td>
                      <td>
                        <RiskBar counts={row.counts_by_severity} total={row.total_findings} height={5} showLabels={false} />
                      </td>
                      <td style={{ textAlign: "right", fontWeight: 700 }}>{row.total_findings}</td>
                      {SEVERITY_COLUMNS.map((col) => {
                        const count = row.counts_by_severity?.[col.key] ?? 0;
                        return (
                          <td
                            key={col.key}
                            style={{
                              textAlign: "right",
                              fontWeight: count > 0 ? 600 : 400,
                              color: count > 0 ? col.color : "var(--text-subtle)",
                            }}
                          >
                            {count}
                          </td>
                        );
                      })}
                      <td style={{ textAlign: "right" }}>
                        <span className={statusBadge} style={{ fontSize: 11 }}>{statusLabel}</span>
                      </td>
                      <td onClick={(e) => e.stopPropagation()} style={{ textAlign: "right" }}>
                        {project ? (
                          <Link href={`/projects/${project.id}`} className="btn btn-ghost btn-sm">
                            Manage →
                          </Link>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Unscanned Projects Section ───────────────────────────────── */}
      {unscannedProjects.length > 0 && !loading && (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-header" style={{ padding: "16px 20px" }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 14 }}>Projects Without Completed Audits ({unscannedProjects.length})</h2>
              <p className="muted" style={{ margin: "2px 0 0", fontSize: 12 }}>
                These projects have been registered but have no scan findings on record
              </p>
            </div>
          </div>

          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Project Name</th>
                  <th>Description</th>
                  <th>Created</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {unscannedProjects.map((proj) => (
                  <tr
                    key={proj.id}
                    className="clickable"
                    onClick={() => {
                      window.location.href = `/projects/${proj.id}`;
                    }}
                  >
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <FolderIcon width={14} height={14} style={{ color: "var(--text-muted)" }} />
                        <span style={{ fontWeight: 600 }}>{proj.name}</span>
                      </div>
                    </td>
                    <td className="muted" style={{ maxWidth: 300 }}>
                      {proj.description || "—"}
                    </td>
                    <td>
                      <span className="muted" style={{ fontSize: 12 }}>{relativeTime(proj.created_at)}</span>
                    </td>
                    <td onClick={(e) => e.stopPropagation()} style={{ textAlign: "right" }}>
                      <Link href={`/projects/${proj.id}`} className="btn btn-secondary btn-sm">
                        Run First Scan →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Recent Scan Activity Audit Trail ─────────────────────────── */}
      {recentScans.length > 0 && !loading && (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-header" style={{ padding: "16px 20px" }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 14 }}>Recent Audit Runs</h2>
              <p className="muted" style={{ margin: "2px 0 0", fontSize: 12 }}>
                Latest security scanner executions
              </p>
            </div>
            <Link href="/scans" className="btn btn-ghost btn-sm" style={{ fontSize: 12 }}>
              View all scans →
            </Link>
          </div>

          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Tool</th>
                  <th>Target</th>
                  <th>Findings</th>
                  <th>Started</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
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
                      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>{scan.tool}</span>
                    </td>
                    <td>
                      <code style={{ fontSize: 12 }}>{scan.target.value}</code>
                    </td>
                    <td>
                      {scan.stats?.findings != null ? (
                        <span style={{ fontWeight: 600 }}>{scan.stats.findings}</span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>
                      <span className="muted" style={{ fontSize: 12 }}>{relativeTime(scan.started_at ?? scan.created_at)}</span>
                    </td>
                    <td onClick={(e) => e.stopPropagation()} style={{ textAlign: "right" }}>
                      <Link href={`/scans/${scan.id}`} className="btn btn-ghost btn-sm">
                        Details →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
