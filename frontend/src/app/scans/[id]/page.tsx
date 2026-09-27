"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import React, { useCallback, useEffect, useMemo, useState, Fragment } from "react";
import {
  api,
  formatDate,
  isTerminal,
  type Finding,
  type Project,
  type Scan,
  type ScanDiff,
  type ScanResult,
  type Severity,
} from "@/lib/api";
import Breadcrumb from "@/components/Breadcrumb";
import SeverityBadge from "@/components/SeverityBadge";
import StatusDot from "@/components/StatusDot";
import KpiCard from "@/components/KpiCard";
import ConfirmModal from "@/components/ConfirmModal";
import EmptyState from "@/components/EmptyState";
import {
  ActivityIcon,
  AlertTriangleIcon,
  ClockIcon,
  TrashIcon,
  SearchIcon,
  FolderIcon,
  CodeIcon,
  ZapIcon,
  ChevronRightIcon,
  CheckIcon,
} from "@/components/icons";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

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

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const scanId = params.id;
  const router = useRouter();

  const [scan, setScan] = useState<Scan | null>(null);
  const [project, setProject] = useState<Project | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "diff" | "raw">("findings");
  const [diffTab, setDiffTab] = useState<"new" | "fixed" | "unchanged">("new");
  const [loading, setLoading] = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [diffLoading, setDiffLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters & Search for findings
  const [query, setQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("");
  const [openFindingId, setOpenFindingId] = useState<string | null>(null);
  const [showRawOutput, setShowRawOutput] = useState(false);

  // Actions
  const [cancelling, setCancelling] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  /* ── Load Scan Data ─────────────────────────────────────────────────── */

  const loadScan = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const scanData = await api.getScan(scanId);
        setScan(scanData);
        setError(null);

        // Fetch project relation if available
        if (scanData.project_id) {
          api.getProject(scanData.project_id)
            .then(setProject)
            .catch(() => setProject(null));
        }

        // Fetch findings, results, and diff if scan has finished or has stats
        if (isTerminal(scanData.status) || (scanData.stats?.findings ?? 0) > 0) {
          if (!silent) {
            setFindingsLoading(true);
            setResultsLoading(true);
            setDiffLoading(true);
          }
          const [findingsData, resultsData, diffData] = await Promise.all([
            api.listFindings(scanId),
            api.listResults(scanId).catch(() => []),
            api.getScanDiff(scanId).catch(() => null),
          ]);
          setFindings(findingsData);
          setResults(resultsData);
          setDiff(diffData);
          setFindingsLoading(false);
          setResultsLoading(false);
          setDiffLoading(false);
        }
      } catch (err) {
        if (!silent) {
          setError(err instanceof Error ? err.message : "Failed to load scan");
        }
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [scanId]
  );

  useEffect(() => {
    void loadScan();
  }, [loadScan]);

  // Live polling for active scans (every 3s)
  useEffect(() => {
    if (!scan || isTerminal(scan.status)) return;
    const interval = setInterval(() => void loadScan(true), 3000);
    return () => clearInterval(interval);
  }, [scan, loadScan]);

  /* ── Actions ────────────────────────────────────────────────────────── */

  async function handleCancel() {
    setCancelling(true);
    setError(null);
    try {
      const updated = await api.cancelScan(scanId);
      setScan(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to cancel scan");
    } finally {
      setCancelling(false);
    }
  }

  async function executeDelete() {
    setIsDeleting(true);
    setError(null);
    try {
      await api.deleteScan(scanId);
      if (scan?.project_id) {
        router.push(`/projects/${scan.project_id}`);
      } else {
        router.push("/scans");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete scan");
      setIsDeleting(false);
      setShowDeleteModal(false);
    }
  }

  /* ── Filter Findings ────────────────────────────────────────────────── */

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      // Severity filter
      if (selectedSeverity && f.severity !== selectedSeverity) {
        return false;
      }

      // Text search
      if (query.trim()) {
        const q = query.toLowerCase();
        const matches =
          f.name.toLowerCase().includes(q) ||
          f.template_id.toLowerCase().includes(q) ||
          f.matched_at.toLowerCase().includes(q) ||
          f.host.toLowerCase().includes(q);
        if (!matches) return false;
      }

      return true;
    });
  }, [findings, selectedSeverity, query]);

  // Severity counts breakdown
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of findings) {
      if (counts[f.severity] !== undefined) {
        counts[f.severity]++;
      }
    }
    return counts;
  }, [findings]);

  /* ── Loading Skeleton State ─────────────────────────────────────────── */

  if (loading && !scan) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
        <div className="skeleton" style={{ height: 20, width: 200, borderRadius: 4 }} />
        <div className="card" style={{ padding: 24 }}>
          <div className="skeleton" style={{ height: 32, width: 280, marginBottom: 12, borderRadius: 6 }} />
          <div className="skeleton" style={{ height: 16, width: 180, borderRadius: 4 }} />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 14 }}>
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="card" style={{ padding: 18 }}>
              <div className="skeleton" style={{ height: 14, width: 60, marginBottom: 10, borderRadius: 4 }} />
              <div className="skeleton" style={{ height: 28, width: 80, borderRadius: 6 }} />
            </div>
          ))}
        </div>
      </div>
    );
  }

  /* ── 404 / Not Found State ─────────────────────────────────────────── */

  if (!scan) {
    return (
      <div style={{ padding: "40px 0" }}>
        <EmptyState
          icon={<AlertTriangleIcon />}
          title="Scan Not Found"
          description={error || "The requested scan could not be found or has been deleted."}
          action={{ label: "Back to Scans", href: "/scans" }}
        />
      </div>
    );
  }

  const active = !isTerminal(scan.status);
  const totalFindings = scan.stats?.findings ?? findings.length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* ── Breadcrumb ──────────────────────────────────────────────── */}
      <Breadcrumb
        items={[
          { label: "Scans", href: "/scans" },
          ...(project
            ? [{ label: project.name, href: `/projects/${project.id}` }]
            : []),
          { label: `${scan.tool} scan #${scan.id.slice(0, 8)}` },
        ]}
      />

      {/* ── Scan Header ─────────────────────────────────────────────── */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div className="page-title-group">
          <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <h1 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0 }}>
              <span style={{ fontFamily: "JetBrains Mono, monospace" }}>{scan.tool}</span>
              <span className="muted" style={{ fontWeight: 400, fontSize: 18 }}>scan</span>
            </h1>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <StatusDot status={scan.status} />
              <span className={`badge ${scan.status}`}>{scan.status}</span>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 13, color: "var(--text-muted)", marginTop: 4, flexWrap: "wrap" }}>
            {project && (
              <Link
                href={`/projects/${project.id}`}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  color: "var(--text)",
                  fontWeight: 500,
                }}
              >
                <FolderIcon width={13} height={13} style={{ color: "var(--accent-hover)" }} />
                {project.name}
              </Link>
            )}
            <span>·</span>
            <span>Target: <code style={{ fontSize: 12 }}>{scan.target.value}</code></span>
            <span>·</span>
            <span>ID: <code style={{ fontSize: 11, color: "var(--text-subtle)" }}>{scan.id}</code></span>
          </div>
        </div>

        {/* Header Action Buttons */}
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {project && (
            <Link href={`/projects/${project.id}`} className="btn btn-secondary btn-sm">
              <FolderIcon width={13} height={13} />
              View project
            </Link>
          )}

          {active && (
            <button
              type="button"
              className="btn btn-danger btn-sm"
              onClick={handleCancel}
              disabled={cancelling}
            >
              {cancelling ? "Cancelling…" : "Cancel scan"}
            </button>
          )}

          <button
            type="button"
            className="btn btn-ghost btn-sm"
            style={{ color: "var(--danger)", borderColor: "rgba(248,81,73,0.3)" }}
            onClick={() => setShowDeleteModal(true)}
            disabled={isDeleting}
          >
            <TrashIcon width={13} height={13} />
            Delete scan
          </button>
        </div>
      </div>

      {/* ── Active Running Banner ────────────────────────────────────── */}
      {active && (
        <div className="card" style={{ borderLeft: "3px solid var(--accent-hover)", background: "rgba(56, 139, 253, 0.04)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <StatusDot status={scan.status} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, fontSize: 14, color: "var(--text)" }}>
                Scanner engine actively executing on <code>{scan.target.value}</code>
              </div>
              <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
                Live results will stream automatically as vulnerabilities are discovered ({formatDuration(scan.started_at, null)} elapsed)
              </div>
            </div>
          </div>
          <div className="scan-progress-bar" style={{ marginTop: 14, height: 3 }}>
            <div className="scan-progress-fill" />
          </div>
        </div>
      )}

      {/* ── Failure / Error Banner ──────────────────────────────────── */}
      {scan.status === "failed" && (
        <div className="card" style={{ borderLeft: "3px solid var(--danger)", background: "rgba(248, 81, 73, 0.04)" }}>
          <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
            <AlertTriangleIcon width={18} height={18} style={{ color: "var(--danger)", flexShrink: 0, marginTop: 2 }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: 14, color: "var(--danger)" }}>
                Scan Execution Failed
              </div>
              <div style={{ fontSize: 13, color: "var(--text)", marginTop: 4, fontFamily: "JetBrains Mono, monospace" }}>
                {scan.error || "Scanner exited with error status. Check target connectivity and firewall rules."}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── General API Error Banner ─────────────────────────────────── */}
      {error && (
        <div className="error-banner">
          <AlertTriangleIcon width={16} height={16} />
          <span>{error}</span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => setError(null)}
            style={{ marginLeft: "auto", padding: "2px 6px" }}
          >
            ✕
          </button>
        </div>
      )}

      {/* ── KPI Summary Cards ────────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 14 }}>
        <KpiCard
          label="Total Findings"
          value={totalFindings}
          sublabel={`${scan.stats?.lines ?? results.length} raw result lines`}
          icon={<ActivityIcon width={16} height={16} />}
          variant={totalFindings > 0 ? "warning" : "default"}
        />
        <KpiCard
          label="Critical Risks"
          value={severityCounts.critical}
          sublabel={severityCounts.critical > 0 ? "Immediate remediation" : "No critical flaws"}
          icon={<AlertTriangleIcon width={16} height={16} />}
          variant={severityCounts.critical > 0 ? "critical" : "success"}
        />
        <KpiCard
          label="High Risks"
          value={severityCounts.high}
          sublabel={`${severityCounts.medium} medium, ${severityCounts.low} low`}
          icon={<AlertTriangleIcon width={16} height={16} />}
          variant={severityCounts.high > 0 ? "high" : "default"}
        />
        <KpiCard
          label="Duration"
          value={formatDuration(scan.started_at, scan.finished_at)}
          sublabel={scan.started_at ? `Started ${relativeTime(scan.started_at)}` : "Pending start"}
          icon={<ClockIcon width={16} height={16} />}
          variant="default"
        />
      </div>

      {/* ── Scan Scope & Configuration Details ───────────────────────── */}
      <div className="card" style={{ padding: "16px 20px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, fontSize: 13 }}>
          <div>
            <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600, letterSpacing: "0.05em", marginBottom: 4 }}>
              Target Value
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span className="badge kind">{scan.target.kind}</span>
              <code style={{ fontSize: 12 }}>{scan.target.value}</code>
            </div>
          </div>

          <div>
            <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600, letterSpacing: "0.05em", marginBottom: 4 }}>
              Tool & Engine
            </div>
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontWeight: 600 }}>{scan.tool}</span>
          </div>

          <div>
            <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600, letterSpacing: "0.05em", marginBottom: 4 }}>
              Created Timestamp
            </div>
            <span title={formatDate(scan.created_at)}>{relativeTime(scan.created_at)} ({formatDate(scan.created_at)})</span>
          </div>

          {scan.config && Object.keys(scan.config).length > 0 && (
            <div style={{ gridColumn: "1 / -1" }}>
              <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600, letterSpacing: "0.05em", marginBottom: 4 }}>
                Active Configuration
              </div>
              <pre
                style={{
                  margin: 0,
                  padding: "8px 12px",
                  borderRadius: "var(--radius-sm)",
                  background: "var(--bg-subtle)",
                  border: "1px solid var(--border)",
                  fontSize: 11,
                  fontFamily: "JetBrains Mono, monospace",
                  overflowX: "auto",
                }}
              >
                {JSON.stringify(scan.config, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* ── MAIN SCAN TABS (Findings vs Weekly Comparison Diff) ────────── */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      <div style={{ display: "flex", gap: 8, borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
        <button
          type="button"
          className={`btn ${activeTab === "findings" ? "btn-primary" : "btn-secondary"} btn-sm`}
          onClick={() => setActiveTab("findings")}
        >
          Findings ({findings.length})
        </button>
        <button
          type="button"
          className={`btn ${activeTab === "diff" ? "btn-primary" : "btn-secondary"} btn-sm`}
          onClick={() => setActiveTab("diff")}
        >
          Comparison & Diff Analysis {diff ? `(${diff.summary.new_count > 0 ? `+${diff.summary.new_count} new` : "Clean"})` : ""}
        </button>
      </div>

      {activeTab === "diff" ? (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-header" style={{ padding: "18px 20px" }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 15 }}>Weekly Scan Comparison & Vulnerability Delta</h2>
              <p className="muted" style={{ margin: "2px 0 0", fontSize: 12 }}>
                {diff?.target_scan_id
                  ? `Comparing current scan with baseline scan #${diff.target_scan_id.slice(0, 8)}`
                  : "No earlier baseline scan was found for this target. This scan serves as the baseline."}
              </p>
            </div>
          </div>

          {diffLoading ? (
            <div style={{ padding: 32 }}>
              <div className="skeleton" style={{ height: 60, borderRadius: 6, marginBottom: 12 }} />
              <div className="skeleton" style={{ height: 120, borderRadius: 6 }} />
            </div>
          ) : !diff || !diff.target_scan_id ? (
            <div style={{ padding: "40px 24px", textAlign: "center" }}>
              <div
                style={{
                  width: 44,
                  height: 44,
                  borderRadius: "50%",
                  background: "rgba(88, 166, 255, 0.12)",
                  color: "var(--accent)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  margin: "0 auto 12px",
                }}
              >
                <ClockIcon width={22} height={22} />
              </div>
              <p style={{ fontWeight: 600, fontSize: 15, margin: "0 0 4px" }}>Initial Baseline Scan</p>
              <p className="muted" style={{ fontSize: 13, margin: 0, maxWidth: 460, marginLeft: "auto", marginRight: "auto" }}>
                There is no previous scan for this target yet. Subsequent weekly scheduled scans will automatically compare against this run to detect new, resolved, and persistent vulnerabilities.
              </p>
            </div>
          ) : (
            <div>
              {/* Diff Summary Cards */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
                  gap: 12,
                  padding: "16px 20px",
                  background: "var(--bg-subtle)",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                <div className="card" style={{ padding: 14, margin: 0 }}>
                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600 }}>New (Introduced)</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: diff.summary.new_count > 0 ? "var(--critical)" : "var(--text)", marginTop: 4 }}>
                    +{diff.summary.new_count}
                  </div>
                </div>
                <div className="card" style={{ padding: 14, margin: 0 }}>
                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600 }}>Fixed (Resolved)</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: diff.summary.fixed_count > 0 ? "var(--success)" : "var(--text)", marginTop: 4 }}>
                    -{diff.summary.fixed_count}
                  </div>
                </div>
                <div className="card" style={{ padding: 14, margin: 0 }}>
                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600 }}>Persistent (Unchanged)</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: "var(--text-muted)", marginTop: 4 }}>
                    {diff.summary.unchanged_count}
                  </div>
                </div>
                <div className="card" style={{ padding: 14, margin: 0 }}>
                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600 }}>Current vs Previous</div>
                  <div style={{ fontSize: 15, fontWeight: 600, color: "var(--text)", marginTop: 8 }}>
                    {diff.summary.current_total} vs {diff.summary.previous_total}
                  </div>
                </div>
              </div>

              {/* Diff Subtabs */}
              <div style={{ padding: "12px 20px", borderBottom: "1px solid var(--border)", display: "flex", gap: 8 }}>
                <button
                  type="button"
                  className={`pill-tab${diffTab === "new" ? " active" : ""}`}
                  style={diffTab === "new" ? { background: "rgba(248, 81, 73, 0.15)", color: "var(--critical)" } : undefined}
                  onClick={() => setDiffTab("new")}
                >
                  🔴 New Flaws ({diff.new_findings.length})
                </button>
                <button
                  type="button"
                  className={`pill-tab${diffTab === "fixed" ? " active" : ""}`}
                  style={diffTab === "fixed" ? { background: "rgba(63, 185, 80, 0.15)", color: "var(--success)" } : undefined}
                  onClick={() => setDiffTab("fixed")}
                >
                  🟢 Resolved Flaws ({diff.fixed_findings.length})
                </button>
                <button
                  type="button"
                  className={`pill-tab${diffTab === "unchanged" ? " active" : ""}`}
                  onClick={() => setDiffTab("unchanged")}
                >
                  🟡 Persistent ({diff.unchanged_findings.length})
                </button>
              </div>

              {/* Diff Findings Table */}
              {(() => {
                const activeFindings =
                  diffTab === "new"
                    ? diff.new_findings
                    : diffTab === "fixed"
                    ? diff.fixed_findings
                    : diff.unchanged_findings;

                if (activeFindings.length === 0) {
                  return (
                    <div style={{ padding: "32px 20px", textAlign: "center" }}>
                      <p className="muted" style={{ fontSize: 13, margin: 0 }}>
                        {diffTab === "new"
                          ? "No new vulnerabilities introduced compared to the previous scan! 🎉"
                          : diffTab === "fixed"
                          ? "No previous vulnerabilities were resolved in this scan."
                          : "No persistent vulnerabilities."}
                      </p>
                    </div>
                  );
                }

                return (
                  <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: 100 }}>Severity</th>
                          <th>Finding Title</th>
                          <th>Matched Location</th>
                          <th>Template / Rule</th>
                          <th>Detected In</th>
                        </tr>
                      </thead>
                      <tbody>
                        {activeFindings.map((f, idx) => (
                          <tr key={`${f.template_id}-${f.matched_at}-${idx}`}>
                            <td>
                              <SeverityBadge severity={f.severity} />
                            </td>
                            <td>
                              <span style={{ fontWeight: 600 }}>{f.name}</span>
                            </td>
                            <td>
                              <code>{f.matched_at}</code>
                            </td>
                            <td>
                              <code>{f.template_id}</code>
                            </td>
                            <td>
                              <span
                                className="badge"
                                style={{
                                  background:
                                    diffTab === "new"
                                      ? "rgba(248, 81, 73, 0.15)"
                                      : diffTab === "fixed"
                                      ? "rgba(63, 185, 80, 0.15)"
                                      : "var(--panel)",
                                  color:
                                    diffTab === "new"
                                      ? "var(--critical)"
                                      : diffTab === "fixed"
                                      ? "var(--success)"
                                      : "var(--text-muted)",
                                }}
                              >
                                {diffTab === "new" ? "New" : diffTab === "fixed" ? "Resolved" : "Unchanged"}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                );
              })()}
            </div>
          )}
        </div>
      ) : (
        /* ── Findings Investigation Center ── */
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-header" style={{ padding: "18px 20px" }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 15 }}>Security Findings & Vulnerabilities</h2>
              <p className="muted" style={{ margin: "2px 0 0", fontSize: 12 }}>
                Detailed vulnerability reports and evidence detected by {scan.tool}
              </p>
            </div>
            {findings.length > 0 && (
              <span className="muted" style={{ fontSize: 12 }}>
                Showing {filteredFindings.length} of {findings.length} findings
              </span>
            )}
          </div>

        {/* ── Filter Bar for Findings ── */}
        {!active && findings.length > 0 && (
          <div
            style={{
              padding: "12px 20px",
              background: "var(--bg-subtle)",
              borderBottom: "1px solid var(--border)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 12,
            }}
          >
            {/* Severity Pill Tabs */}
            <div className="pill-tabs" style={{ background: "var(--panel)" }}>
              <button
                type="button"
                className={`pill-tab${selectedSeverity === "" ? " active" : ""}`}
                onClick={() => setSelectedSeverity("")}
              >
                All ({findings.length})
              </button>
              {SEVERITY_ORDER.map((sev) => {
                const count = severityCounts[sev] ?? 0;
                if (count === 0) return null;
                return (
                  <button
                    key={sev}
                    type="button"
                    className={`pill-tab sev-${sev}${selectedSeverity === sev ? " active" : ""}`}
                    onClick={() => setSelectedSeverity(sev)}
                  >
                    {sev} ({count})
                  </button>
                );
              })}
            </div>

            {/* Search Input */}
            <div style={{ position: "relative", minWidth: 220 }}>
              <SearchIcon
                width={13}
                height={13}
                style={{
                  position: "absolute",
                  left: 10,
                  top: "50%",
                  transform: "translateY(-50%)",
                  color: "var(--text-subtle)",
                  pointerEvents: "none",
                }}
              />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search finding name, template, host…"
                style={{ paddingLeft: 28, width: "100%", fontSize: 12 }}
              />
            </div>
          </div>
        )}

        {/* ── Findings Content State ── */}
        {active ? (
          <div style={{ padding: "48px 24px", textAlign: "center" }}>
            <ActivityIcon width={28} height={28} style={{ color: "var(--accent-hover)", margin: "0 auto 12px" }} />
            <p style={{ fontWeight: 600, fontSize: 14, margin: "0 0 4px" }}>Scan in progress</p>
            <p className="muted" style={{ fontSize: 13, margin: 0 }}>
              Findings will appear once the scanner finishes processing target scope.
            </p>
          </div>
        ) : findingsLoading ? (
          <div style={{ padding: 32 }}>
            {[1, 2, 3].map((i) => (
              <div key={i} className="skeleton" style={{ height: 44, borderRadius: 6, marginBottom: 8 }} />
            ))}
          </div>
        ) : findings.length === 0 ? (
          <div style={{ padding: "48px 24px", textAlign: "center" }}>
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: "50%",
                background: "rgba(63, 185, 80, 0.12)",
                color: "var(--success)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                margin: "0 auto 12px",
              }}
            >
              <CheckIcon width={22} height={22} />
            </div>
            <p style={{ fontWeight: 600, fontSize: 15, margin: "0 0 4px" }}>No Vulnerabilities Detected</p>
            <p className="muted" style={{ fontSize: 13, margin: 0, maxWidth: 380, marginLeft: "auto", marginRight: "auto" }}>
              The {scan.tool} scanner completed successfully and found zero security flaws for this target.
            </p>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div style={{ padding: "40px 20px", textAlign: "center" }}>
            <p className="muted" style={{ margin: "0 0 12px", fontSize: 13 }}>
              No findings match the current filter or search criteria.
            </p>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => {
                setSelectedSeverity("");
                setQuery("");
              }}
            >
              Clear filters
            </button>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 100 }}>Severity</th>
                  <th>Finding Title</th>
                  <th>Matched Location</th>
                  <th>Template / Rule</th>
                  <th>First Seen</th>
                  <th style={{ width: 40 }} />
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((finding, idx) => {
                  const findingKey = `${finding.template_id}|${finding.matched_at || finding.host}|${idx}`;
                  const isOpen = openFindingId === findingKey;

                  return (
                    <Fragment key={findingKey}>
                      <tr
                        className="clickable"
                        onClick={() => setOpenFindingId(isOpen ? null : findingKey)}
                        style={isOpen ? { background: "var(--panel-hover)" } : undefined}
                      >
                        <td>
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td>
                          <span style={{ fontWeight: 600, color: "var(--text)" }}>{finding.name}</span>
                        </td>
                        <td>
                          <code style={{ fontSize: 12 }}>{finding.matched_at}</code>
                        </td>
                        <td>
                          <code style={{ fontSize: 12, color: "var(--text-muted)" }}>{finding.template_id}</code>
                        </td>
                        <td>
                          <span className="muted" style={{ fontSize: 12 }} title={formatDate(finding.first_seen_at)}>
                            {relativeTime(finding.first_seen_at)}
                          </span>
                        </td>
                        <td style={{ textAlign: "right", color: "var(--text-subtle)" }}>
                          <ChevronRightIcon
                            width={14}
                            height={14}
                            style={{
                              transform: isOpen ? "rotate(90deg)" : "rotate(0deg)",
                              transition: "transform 150ms ease",
                            }}
                          />
                        </td>
                      </tr>

                      {/* Expanded Investigation Panel */}
                      {isOpen && (
                        <tr style={{ background: "var(--bg-subtle)" }}>
                          <td colSpan={6} style={{ padding: "16px 20px" }}>
                            <div
                              style={{
                                display: "flex",
                                flexDirection: "column",
                                gap: 14,
                                background: "var(--panel)",
                                padding: 16,
                                borderRadius: "var(--radius-md)",
                                border: "1px solid var(--border)",
                              }}
                            >
                              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, fontSize: 12 }}>
                                <div>
                                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600, letterSpacing: "0.05em", marginBottom: 4 }}>
                                    Affected Host
                                  </div>
                                  <code>{finding.host}</code>
                                </div>

                                <div>
                                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600, letterSpacing: "0.05em", marginBottom: 4 }}>
                                    Template / Rule ID
                                  </div>
                                  <code>{finding.template_id}</code>
                                </div>

                                <div>
                                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600, letterSpacing: "0.05em", marginBottom: 4 }}>
                                    First Detected
                                  </div>
                                  <span>{formatDate(finding.first_seen_at)}</span>
                                </div>

                                <div>
                                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600, letterSpacing: "0.05em", marginBottom: 4 }}>
                                    Last Observed
                                  </div>
                                  <span>{formatDate(finding.last_seen_at)}</span>
                                </div>
                              </div>

                              {/* Extracted Technical Evidence */}
                              {finding.extracted && finding.extracted.length > 0 && (
                                <div>
                                  <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", fontWeight: 600, letterSpacing: "0.05em", marginBottom: 6 }}>
                                    Extracted Evidence & Payloads
                                  </div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                                    {finding.extracted.map((item, idx) => (
                                      <pre
                                        key={idx}
                                        style={{
                                          margin: 0,
                                          padding: "6px 10px",
                                          borderRadius: "var(--radius-sm)",
                                          background: "var(--bg)",
                                          border: "1px solid var(--border)",
                                          fontSize: 11,
                                          fontFamily: "JetBrains Mono, monospace",
                                          whiteSpace: "pre-wrap",
                                          wordBreak: "break-all",
                                          color: "var(--text)",
                                        }}
                                      >
                                        {item}
                                      </pre>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* ── RAW SCANNER OUTPUT ─────────────────────────────────────────── */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <div
          className="card-header"
          style={{ padding: "16px 20px", cursor: "pointer" }}
          onClick={() => setShowRawOutput((v) => !v)}
        >
          <h2 style={{ margin: 0, fontSize: 14, display: "flex", alignItems: "center", gap: 8 }}>
            <CodeIcon width={15} height={15} style={{ color: "var(--text-muted)" }} />
            Raw Scanner Output ({results.length} lines)
            <span className="muted" style={{ fontSize: 12, fontWeight: 400 }}>
              {showRawOutput ? "(click to collapse)" : "(click to expand)"}
            </span>
          </h2>
          <button type="button" className="btn btn-ghost btn-sm" style={{ padding: "2px 6px" }}>
            {showRawOutput ? "▲ Collapse" : "▼ Expand"}
          </button>
        </div>

        {showRawOutput && (
          <div style={{ padding: "16px 20px", background: "var(--bg-subtle)", borderTop: "1px solid var(--border)" }}>
            {resultsLoading ? (
              <div className="skeleton" style={{ height: 100, borderRadius: 6 }} />
            ) : results.length === 0 ? (
              <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                {active ? "Raw output stream will appear once available." : "No raw output lines returned for this scan run."}
              </p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {results.map((result) => (
                  <div
                    key={result.id}
                    style={{
                      padding: "8px 12px",
                      borderRadius: "var(--radius-sm)",
                      background: "var(--panel)",
                      border: "1px solid var(--border)",
                      fontSize: 11,
                    }}
                  >
                    <div className="muted" style={{ marginBottom: 4, fontFamily: "JetBrains Mono, monospace" }}>
                      Line #{result.id} · {result.tool} · {formatDate(result.created_at)}
                    </div>
                    <pre
                      style={{
                        margin: 0,
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: 11,
                        lineHeight: 1.4,
                        overflowX: "auto",
                      }}
                    >
                      {JSON.stringify(result.raw, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Scan Deletion Confirm Modal ───────────────────────────────── */}
      <ConfirmModal
        isOpen={showDeleteModal}
        title="Delete Scan Run?"
        message={`Are you sure you want to permanently delete this ${scan.tool} scan run and its discovered findings for "${scan.target.value}"?`}
        confirmLabel="Delete Scan"
        cancelLabel="Cancel"
        isDestructive
        isBusy={isDeleting}
        onConfirm={executeDelete}
        onCancel={() => setShowDeleteModal(false)}
      />
    </div>
  );
}
