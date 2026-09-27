"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  api,
  isTerminal,
  type Project,
  type Scan,
  type OverviewData,
} from "@/lib/api";
import StatusDot from "@/components/StatusDot";
import EmptyState from "@/components/EmptyState";
import KpiCard from "@/components/KpiCard";
import RiskBar from "@/components/RiskBar";
import {
  ShieldIcon,
  FolderIcon,
  ActivityIcon,
  PlusIcon,
  AlertTriangleIcon,
  ZapIcon,
  ArrowRightIcon,
  ClockIcon,
} from "@/components/icons";

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

function duration(start: string | null): string {
  if (!start) return "—";
  const secs = Math.max(0, Math.round((Date.now() - new Date(start).getTime()) / 1000));
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}m ${s}s`;
}

export default function DashboardPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [projectsData, scansData, overviewData] = await Promise.all([
        api.listProjects(),
        api.listAllScans(50),
        api.getOverview().catch(() => null),
      ]);
      setProjects(projectsData);
      setScans(scansData);
      setOverview(overviewData);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Live polling only while active scans exist
  useEffect(() => {
    const hasActive = scans.some((s) => !isTerminal(s.status));
    if (!hasActive) return;
    const interval = setInterval(() => void load(), 3000);
    return () => clearInterval(interval);
  }, [scans, load]);

  const activeScans = scans.filter((s) => !isTerminal(s.status));
  const recentScans = scans.slice(0, 10);
  const totalFindings = scans.reduce((sum, s) => sum + (s.stats?.findings ?? 0), 0);
  const criticalCount = scans.reduce(
    (sum, s) => sum + (s.stats?.by_severity?.["critical"] ?? 0),
    0,
  );
  const highCount = scans.reduce(
    (sum, s) => sum + (s.stats?.by_severity?.["high"] ?? 0),
    0,
  );

  const isFirstTime = !loading && projects.length === 0 && scans.length === 0;

  // Map project name to project ID for quick navigation
  const projectMap = new Map(projects.map((p) => [p.name, p.id]));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* ── Page Header ─────────────────────────────────────────────── */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div className="page-title-group">
          <h1>Security Overview</h1>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            Real-time security posture across connected repositories, web apps, and assets
          </p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Link href="/projects" className="btn btn-secondary btn-sm">
            <FolderIcon width={13} height={13} />
            View all projects
          </Link>
          <Link href="/projects" className="btn btn-primary btn-sm">
            <PlusIcon width={13} height={13} />
            New project
          </Link>
        </div>
      </div>

      {/* ── Error Banner ────────────────────────────────────────────── */}
      {error && (
        <div className="error-banner">
          <AlertTriangleIcon width={16} height={16} />
          <span>{error}</span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => void load()}
            style={{ marginLeft: "auto", padding: "2px 8px" }}
          >
            Retry
          </button>
        </div>
      )}

      {/* ── First-time Empty State ───────────────────────────────────── */}
      {isFirstTime && (
        <div className="card" style={{ textAlign: "center", padding: "48px 24px" }}>
          <div
            style={{
              width: 52,
              height: 52,
              borderRadius: "var(--radius-xl)",
              background: "var(--panel-hover)",
              border: "1px solid var(--border)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              margin: "0 auto 20px",
            }}
          >
            <ShieldIcon width={24} height={24} style={{ color: "var(--accent)" }} strokeWidth={1.5} />
          </div>
          <h2 style={{ fontSize: 18, marginBottom: 8 }}>Welcome to SecPlat ASPM</h2>
          <p className="muted" style={{ maxWidth: 420, margin: "0 auto 24px", lineHeight: 1.6 }}>
            Your application security posture management hub. Create your first project, add target URLs or repositories, and run continuous audits.
          </p>
          <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
            <Link href="/projects" className="btn btn-primary">
              <PlusIcon width={14} height={14} />
              Create first project
            </Link>
          </div>
        </div>
      )}

      {/* ── KPI Metrics Grid ─────────────────────────────────────────── */}
      {!isFirstTime && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 16 }}>
          {loading ? (
            [1, 2, 3, 4].map((i) => (
              <div key={i} className="card" style={{ padding: 18 }}>
                <div className="skeleton" style={{ height: 14, width: 80, marginBottom: 12, borderRadius: 4 }} />
                <div className="skeleton" style={{ height: 32, width: 60, borderRadius: 6 }} />
              </div>
            ))
          ) : (
            <>
              <KpiCard
                label="Monitored Projects"
                value={projects.length}
                sublabel={`${overview?.projects_reported ?? 0} with completed audits`}
                icon={<FolderIcon width={18} height={18} />}
                variant="default"
              />
              <KpiCard
                label="Active Scans"
                value={activeScans.length}
                sublabel={activeScans.length > 0 ? "Orchestrating tools in real-time" : "All queues idle"}
                icon={<ZapIcon width={18} height={18} />}
                variant={activeScans.length > 0 ? "accent" : "default"}
              />
              <KpiCard
                label="Total Findings"
                value={totalFindings}
                sublabel={`${highCount} high severity risks`}
                icon={<ActivityIcon width={18} height={18} />}
                variant="default"
              />
              <KpiCard
                label="Critical Findings"
                value={criticalCount}
                sublabel={criticalCount > 0 ? "Immediate attention required" : "Zero critical vulnerabilities"}
                icon={<AlertTriangleIcon width={18} height={18} />}
                variant={criticalCount > 0 ? "critical" : "default"}
              />
            </>
          )}
        </div>
      )}



      {/* ── Active Scans Live Section ─────────────────────────────────── */}
      {!loading && activeScans.length > 0 && (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-header" style={{ padding: "16px 20px 12px" }}>
            <h2 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0, fontSize: 14 }}>
              <span style={{ color: "var(--accent-hover)" }}>
                <ZapIcon width={16} height={16} />
              </span>
              Active Security Scans
              <span className="topbar-scan-pill active" style={{ fontSize: 11, padding: "1px 8px" }}>
                {activeScans.length} running
              </span>
            </h2>
          </div>
          <div className="scan-progress-bar" style={{ height: 2, margin: 0 }}>
            <div className="scan-progress-fill" />
          </div>
          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Tool</th>
                  <th>Target</th>
                  <th>Elapsed</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {activeScans.map((scan) => (
                  <tr key={scan.id} className="clickable" onClick={() => { window.location.href = `/scans/${scan.id}`; }}>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <StatusDot status={scan.status} />
                        <span className={`badge ${scan.status}`}>{scan.status}</span>
                      </div>
                    </td>
                    <td>
                      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, color: "var(--accent-hover)", fontWeight: 600 }}>
                        {scan.tool}
                      </span>
                    </td>
                    <td>
                      <code style={{ fontSize: 12 }}>{scan.target.value}</code>
                    </td>
                    <td>
                      <span className="muted" style={{ fontSize: 12, display: "inline-flex", alignItems: "center", gap: 4 }}>
                        <ClockIcon width={12} height={12} />
                        {duration(scan.started_at ?? scan.created_at)}
                      </span>
                    </td>
                    <td onClick={(e) => e.stopPropagation()} style={{ textAlign: "right" }}>
                      <Link href={`/scans/${scan.id}`} className="btn btn-ghost btn-sm">
                        View stream →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Project Security Posture Matrix ──────────────────────────── */}
      {!loading && !isFirstTime && (overview?.rows?.length ?? 0) > 0 && (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-header" style={{ padding: "18px 20px" }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 15 }}>Projects Security Posture</h2>
              <p className="muted" style={{ margin: "2px 0 0", fontSize: 12 }}>
                Severity distribution per project based on latest audit
              </p>
            </div>
            <Link href="/reports" className="btn btn-ghost btn-sm" style={{ fontSize: 12 }}>
              Detailed Report →
            </Link>
          </div>
          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Project Name</th>
                  <th style={{ width: 220 }}>Severity Distribution</th>
                  <th style={{ textAlign: "right" }}>Total Findings</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {overview?.rows.map((row) => {
                  const projectId = projectMap.get(row.project_name);
                  return (
                    <tr
                      key={row.project_name}
                      className={projectId ? "clickable" : undefined}
                      onClick={() => {
                        if (projectId) window.location.href = `/projects/${projectId}`;
                      }}
                    >
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <FolderIcon width={14} height={14} style={{ color: "var(--accent-hover)", flexShrink: 0 }} />
                          <span style={{ fontWeight: 600, color: "var(--text)" }}>{row.project_name}</span>
                        </div>
                      </td>
                      <td>
                        <RiskBar counts={row.counts_by_severity} total={row.total_findings} height={6} showLabels={false} />
                      </td>
                      <td style={{ textAlign: "right", fontWeight: 700 }}>
                        {row.total_findings > 0 ? (
                          <span>{row.total_findings}</span>
                        ) : (
                          <span style={{ color: "var(--success)", fontWeight: 500, fontSize: 12 }}>0 (Clean)</span>
                        )}
                      </td>
                      <td onClick={(e) => e.stopPropagation()} style={{ textAlign: "right" }}>
                        {projectId ? (
                          <Link href={`/projects/${projectId}`} className="btn btn-ghost btn-sm">
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

      {/* ── Recent Scan Activity ─────────────────────────────────────── */}
      {!loading && recentScans.length > 0 && (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-header" style={{ padding: "18px 20px" }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 15 }}>Recent Audit Activity</h2>
              <p className="muted" style={{ margin: "2px 0 0", fontSize: 12 }}>
                Latest 10 security scans executed across all projects
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
                  <th>When</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="clickable"
                    onClick={() => { window.location.href = `/scans/${scan.id}`; }}
                  >
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <StatusDot status={scan.status} />
                        <span className={`badge ${scan.status}`}>{scan.status}</span>
                      </div>
                    </td>
                    <td>
                      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, color: "var(--text)" }}>
                        {scan.tool}
                      </span>
                    </td>
                    <td>
                      <code style={{ fontSize: 12 }}>{scan.target.value}</code>
                    </td>
                    <td>
                      {scan.stats?.findings != null ? (
                        <span style={{ fontWeight: 600 }}>
                          {scan.stats.findings}
                          {(scan.stats.by_severity?.["critical"] ?? 0) > 0 && (
                            <span style={{ marginLeft: 6 }}>
                              <span className="badge critical" style={{ fontSize: 10, padding: "1px 5px" }}>
                                {scan.stats.by_severity?.["critical"]} crit
                              </span>
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>
                      <span className="muted" style={{ fontSize: 12 }} title={new Date(scan.started_at ?? scan.created_at).toLocaleString()}>
                        {relativeTime(scan.started_at ?? scan.created_at)}
                      </span>
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

      {/* ── Empty State: Has Projects but No Scans ─────────────────────── */}
      {!loading && !isFirstTime && scans.length === 0 && (
        <EmptyState
          icon={<ActivityIcon />}
          title="No security scans executed yet"
          description="Select a project and launch your first scan (Nuclei, Semgrep, Trivy, Gitleaks, or Subfinder)."
          action={{ label: "Go to Projects", href: "/projects" }}
        />
      )}
    </div>
  );
}
