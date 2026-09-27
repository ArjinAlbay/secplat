"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  isTerminal,
  type Project,
  type Scan,
} from "@/lib/api";
import EmptyState from "@/components/EmptyState";
import KpiCard from "@/components/KpiCard";
import ConfirmModal from "@/components/ConfirmModal";
import {
  ActivityIcon,
  ZapIcon,
  AlertTriangleIcon,
  ClockIcon,
} from "@/components/icons";
import ScanRunsTable from "@/components/ScanRunsTable";

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Deletion Modal
  const [scanToDelete, setScanToDelete] = useState<Scan | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [scansData, projectsData] = await Promise.all([
        api.listAllScans(100),
        api.listProjects().catch(() => []),
      ]);
      setScans(scansData);
      setProjects(projectsData);
      setError(null);
    } catch (err) {
      if (!silent) {
        setError(err instanceof Error ? err.message : "Failed to load scans");
      }
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Live polling for active scans (every 3s)
  useEffect(() => {
    const hasActive = scans.some((s) => !isTerminal(s.status));
    if (!hasActive) return;
    const interval = setInterval(() => void load(true), 3000);
    return () => clearInterval(interval);
  }, [scans, load]);

  // Map project ID to Project
  const projectMap = useMemo(() => {
    const map = new Map<string, Project>();
    for (const p of projects) {
      map.set(p.id, p);
    }
    return map;
  }, [projects]);

  // Summary KPI Calculations
  const runningCount = scans.filter((s) => s.status === "running").length;
  const queuedCount = scans.filter((s) => s.status === "queued" || s.status === "pending").length;
  const completedCount = scans.filter((s) => s.status === "completed").length;
  const failedCount = scans.filter((s) => s.status === "failed").length;

  async function executeDeleteScan() {
    if (!scanToDelete) return;
    setIsDeleting(true);
    setError(null);
    try {
      await api.deleteScan(scanToDelete.id);
      setScanToDelete(null);
      await load(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete scan");
    } finally {
      setIsDeleting(false);
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* ── Page Header ─────────────────────────────────────────────── */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div className="page-title-group">
          <h1>Scans</h1>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            Global security audit sessions & runs across all monitored projects ({scans.length} total)
          </p>
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
            style={{ marginLeft: "auto", padding: "2px 6px" }}
          >
            Retry
          </button>
        </div>
      )}

      {/* ── KPI Summary Cards ────────────────────────────────────────── */}
      {scans.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 14 }}>
          <KpiCard
            label="Total Audits"
            value={scans.length}
            sublabel="All executed runs"
            icon={<ActivityIcon width={16} height={16} />}
            variant="default"
          />
          <KpiCard
            label="Running"
            value={runningCount}
            sublabel={runningCount > 0 ? "Actively scanning" : "No running jobs"}
            icon={<ZapIcon width={16} height={16} />}
            variant={runningCount > 0 ? "accent" : "default"}
          />
          <KpiCard
            label="Queued"
            value={queuedCount}
            sublabel={queuedCount > 0 ? "Pending worker pickup" : "Queue is clear"}
            icon={<ClockIcon width={16} height={16} />}
            variant={queuedCount > 0 ? "warning" : "default"}
          />
          <KpiCard
            label="Completed"
            value={completedCount}
            sublabel="Finished successfully"
            icon={<ActivityIcon width={16} height={16} />}
            variant="success"
          />
          <KpiCard
            label="Failed"
            value={failedCount}
            sublabel={failedCount > 0 ? "Execution errors" : "Zero failures"}
            icon={<AlertTriangleIcon width={16} height={16} />}
            variant={failedCount > 0 ? "critical" : "default"}
          />
        </div>
      )}

      {/* ── Scans Table ─────────────────────────────────────────────── */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        {loading ? (
          <div style={{ padding: 32 }}>
            {[1, 2, 3, 4, 5].map((i) => (
              <div
                key={i}
                className="skeleton"
                style={{ height: 44, borderRadius: 6, marginBottom: 8 }}
              />
            ))}
          </div>
        ) : scans.length === 0 ? (
          <EmptyState
            icon={<ActivityIcon />}
            title="No scans executed yet"
            description="Go to any project and launch your first security scan (DAST, SAST, SCA, or Secrets)."
            action={{ label: "Go to Projects", href: "/projects" }}
          />
        ) : (
          <ScanRunsTable
            scans={scans}
            onDeleteScan={(s) => setScanToDelete(s)}
            showProjectName={true}
            projectMap={projectMap}
          />
        )}
      </div>

      {/* ── Scan Delete Confirm Modal ─────────────────────────────────── */}
      <ConfirmModal
        isOpen={scanToDelete !== null}
        title="Delete Scan?"
        message={`Are you sure you want to permanently delete this ${scanToDelete?.tool} scan run and its findings for "${scanToDelete?.target.value}"?`}
        confirmLabel="Delete Scan"
        cancelLabel="Cancel"
        isDestructive
        isBusy={isDeleting}
        onConfirm={executeDeleteScan}
        onCancel={() => setScanToDelete(null)}
      />
    </div>
  );
}
