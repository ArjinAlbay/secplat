"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  api,
  type Project,
  type OverviewData,
  type OverviewRow,
} from "@/lib/api";
import EmptyState from "@/components/EmptyState";
import RiskBar from "@/components/RiskBar";
import BulkToolbar from "@/components/BulkToolbar";
import ConfirmModal from "@/components/ConfirmModal";
import {
  FolderIcon,
  PlusIcon,
  SearchIcon,
  TrashIcon,
  AlertTriangleIcon,
  CheckIcon,
} from "@/components/icons";

function relativeTime(iso: string): string {
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

type SeverityFilter = "all" | "critical" | "high" | "clean" | "unscanned";

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Filters & Search
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");

  // Create project form
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);

  // Selection & Bulk Actions
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [isBulkDeleting, setIsBulkDeleting] = useState(false);
  const [showBulkDeleteModal, setShowBulkDeleteModal] = useState(false);

  // Single project deletion modal state
  const [projectToDelete, setProjectToDelete] = useState<Project | null>(null);
  const [isDeletingSingle, setIsDeletingSingle] = useState(false);

  const load = useCallback(async () => {
    try {
      const [projectsData, overviewData] = await Promise.all([
        api.listProjects(),
        api.getOverview().catch(() => null),
      ]);
      setProjects(projectsData);
      setOverview(overviewData);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load projects");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (showForm) nameRef.current?.focus();
  }, [showForm]);

  // Map overview row by project name
  const overviewMap = useMemo(() => {
    const map = new Map<string, OverviewRow>();
    if (overview?.rows) {
      for (const row of overview.rows) {
        map.set(row.project_name, row);
      }
    }
    return map;
  }, [overview]);

  // Filter projects
  const filtered = useMemo(() => {
    return projects.filter((p) => {
      // Query filter
      const matchesQuery =
        p.name.toLowerCase().includes(query.toLowerCase()) ||
        (p.description ?? "").toLowerCase().includes(query.toLowerCase());
      if (!matchesQuery) return false;

      // Severity filter
      const row = overviewMap.get(p.name);
      if (severityFilter === "critical") {
        return (row?.counts_by_severity?.["critical"] ?? 0) > 0;
      }
      if (severityFilter === "high") {
        return (row?.counts_by_severity?.["high"] ?? 0) > 0;
      }
      if (severityFilter === "clean") {
        return row != null && row.total_findings === 0;
      }
      if (severityFilter === "unscanned") {
        return row == null;
      }
      return true;
    });
  }, [projects, query, severityFilter, overviewMap]);

  // Checkbox selection handlers
  const allFilteredSelected =
    filtered.length > 0 && filtered.every((p) => selectedIds.has(p.id));

  function toggleSelectAll() {
    if (allFilteredSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((p) => p.id)));
    }
  }

  function toggleSelectRow(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  // Create Project
  async function submitCreate(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.createProject({
        name: name.trim(),
        description: description.trim() || undefined,
      });
      setName("");
      setDescription("");
      setShowForm(false);
      setSuccessMsg(`Project "${name.trim()}" created successfully`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create project");
    } finally {
      setBusy(false);
    }
  }

  // Single Project Delete execution
  async function executeSingleDelete() {
    if (!projectToDelete) return;
    setIsDeletingSingle(true);
    setError(null);
    try {
      await api.deleteProject(projectToDelete.id);
      setSuccessMsg(`Project "${projectToDelete.name}" deleted successfully`);
      setProjectToDelete(null);
      setSelectedIds((prev) => {
        const next = new Set(prev);
        next.delete(projectToDelete.id);
        return next;
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete project");
    } finally {
      setIsDeletingSingle(false);
    }
  }

  // Bulk Delete execution
  async function executeBulkDelete() {
    const idsToDelete = Array.from(selectedIds);
    if (idsToDelete.length === 0) return;

    setIsBulkDeleting(true);
    setError(null);

    const results = await Promise.allSettled(
      idsToDelete.map(async (id) => {
        await api.deleteProject(id);
        return id;
      })
    );

    const successfulIds: string[] = [];
    const failedIds: string[] = [];

    results.forEach((res, index) => {
      if (res.status === "fulfilled") {
        successfulIds.push(idsToDelete[index]);
      } else {
        failedIds.push(idsToDelete[index]);
      }
    });

    if (failedIds.length === 0) {
      setSuccessMsg(`Successfully deleted ${successfulIds.length} project(s).`);
      setSelectedIds(new Set());
    } else if (successfulIds.length > 0) {
      setError(`Deleted ${successfulIds.length} project(s), but ${failedIds.length} project(s) failed to delete.`);
      setSelectedIds(new Set(failedIds));
    } else {
      setError(`Failed to delete all ${failedIds.length} selected project(s).`);
    }

    setShowBulkDeleteModal(false);
    setIsBulkDeleting(false);
    await load();
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* ── Page Header ─────────────────────────────────────────────── */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div className="page-title-group">
          <h1>Projects</h1>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            Manage repositories, web assets, and security posture scopes ({projects.length} project{projects.length !== 1 ? "s" : ""})
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary btn-sm"
          onClick={() => setShowForm((v) => !v)}
        >
          <PlusIcon width={14} height={14} />
          New project
        </button>
      </div>

      {/* ── Error & Success Banners ─────────────────────────────────── */}
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

      {successMsg && (
        <div
          style={{
            padding: "10px 14px",
            borderRadius: "var(--radius-md)",
            background: "rgba(63, 185, 80, 0.12)",
            border: "1px solid rgba(63, 185, 80, 0.3)",
            color: "var(--success)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            fontSize: 13,
          }}
        >
          <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <CheckIcon width={14} height={14} />
            {successMsg}
          </span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => setSuccessMsg(null)}
            style={{ color: "var(--success)", padding: "2px 6px" }}
          >
            ✕
          </button>
        </div>
      )}

      {/* ── Create Project Drawer / Card ────────────────────────────── */}
      {showForm && (
        <div className="card" style={{ animation: "fade-in 150ms ease" }}>
          <div className="card-header">
            <h2>Create New Project</h2>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => setShowForm(false)}
              style={{ padding: "4px 8px" }}
            >
              ✕
            </button>
          </div>
          <form className="form-row" onSubmit={submitCreate}>
            <div className="field" style={{ flex: 1, minWidth: 180 }}>
              <label htmlFor="project-name">Project Name *</label>
              <input
                id="project-name"
                ref={nameRef}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. payment-gateway or acme-web"
                required
              />
            </div>
            <div className="field" style={{ flex: 2, minWidth: 220 }}>
              <label htmlFor="project-desc">Description (Optional)</label>
              <input
                id="project-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Repository or application purpose"
              />
            </div>
            <div className="field" style={{ justifyContent: "flex-end" }}>
              <button type="submit" className="btn btn-primary" disabled={busy || !name.trim()}>
                {busy ? "Creating…" : "Create project"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ── Filters & Search Toolbar ─────────────────────────────────── */}
      {projects.length > 0 && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <div style={{ position: "relative", flex: "1 1 240px", maxWidth: 360 }}>
            <SearchIcon
              width={14}
              height={14}
              style={{
                position: "absolute",
                left: 11,
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--text-subtle)",
                pointerEvents: "none",
              }}
            />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by project name or description…"
              style={{ paddingLeft: 32, width: "100%" }}
            />
          </div>

          {/* Severity filter pills */}
          <div className="pill-tabs" style={{ background: "var(--panel)", border: "1px solid var(--border)" }}>
            <button
              type="button"
              className={`pill-tab${severityFilter === "all" ? " active" : ""}`}
              onClick={() => setSeverityFilter("all")}
            >
              All
            </button>
            <button
              type="button"
              className={`pill-tab sev-critical${severityFilter === "critical" ? " active" : ""}`}
              onClick={() => setSeverityFilter("critical")}
            >
              Critical Risk
            </button>
            <button
              type="button"
              className={`pill-tab sev-high${severityFilter === "high" ? " active" : ""}`}
              onClick={() => setSeverityFilter("high")}
            >
              High Risk
            </button>
            <button
              type="button"
              className={`pill-tab${severityFilter === "clean" ? " active" : ""}`}
              onClick={() => setSeverityFilter("clean")}
            >
              Clean (0 Findings)
            </button>
            <button
              type="button"
              className={`pill-tab${severityFilter === "unscanned" ? " active" : ""}`}
              onClick={() => setSeverityFilter("unscanned")}
            >
              Not Scanned
            </button>
          </div>
        </div>
      )}

      {/* ── Project Table Card ───────────────────────────────────────── */}
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
        ) : projects.length === 0 ? (
          <EmptyState
            icon={<FolderIcon />}
            title="No projects configured yet"
            description="Create a project to define scan scopes, add target URLs or code directories."
            action={{ label: "Create First Project", href: "#" }}
          />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<SearchIcon />}
            title="No matching projects"
            description={`No projects match the current search "${query}" or selected filter.`}
          />
        ) : (
          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th className="th-checkbox">
                    <input
                      type="checkbox"
                      className="table-checkbox"
                      checked={allFilteredSelected}
                      onChange={toggleSelectAll}
                      aria-label="Select all projects"
                    />
                  </th>
                  <th>Project Name</th>
                  <th>Description</th>
                  <th style={{ width: 220 }}>Security Status</th>
                  <th style={{ textAlign: "right" }}>Findings</th>
                  <th>Created</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((project) => {
                  const isSelected = selectedIds.has(project.id);
                  const row = overviewMap.get(project.name);
                  const totalFindings = row?.total_findings ?? null;
                  const critCount = row?.counts_by_severity?.["critical"] ?? 0;
                  const highCount = row?.counts_by_severity?.["high"] ?? 0;

                  return (
                    <tr
                      key={project.id}
                      className={isSelected ? "row-selected clickable" : "clickable"}
                      onClick={() => {
                        window.location.href = `/projects/${project.id}`;
                      }}
                      style={isSelected ? { background: "var(--panel-hover)" } : undefined}
                    >
                      <td className="td-checkbox" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          className="table-checkbox"
                          checked={isSelected}
                          onChange={() => toggleSelectRow(project.id)}
                          aria-label={`Select project ${project.name}`}
                        />
                      </td>
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <FolderIcon
                            width={15}
                            height={15}
                            style={{ color: "var(--accent-hover)", flexShrink: 0 }}
                          />
                          <Link
                            href={`/projects/${project.id}`}
                            style={{ fontWeight: 600, color: "var(--text)" }}
                            onClick={(e) => e.stopPropagation()}
                          >
                            {project.name}
                          </Link>
                        </div>
                      </td>
                      <td className="muted" style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {project.description ?? <span className="subtle">—</span>}
                      </td>
                      <td>
                        {row != null ? (
                          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                            <RiskBar
                              counts={row.counts_by_severity}
                              total={row.total_findings}
                              height={5}
                              showLabels={false}
                            />
                            <div style={{ display: "flex", gap: 4 }}>
                              {critCount > 0 && <span className="badge critical" style={{ fontSize: 10, padding: "0 4px" }}>{critCount} crit</span>}
                              {highCount > 0 && <span className="badge high" style={{ fontSize: 10, padding: "0 4px" }}>{highCount} high</span>}
                            </div>
                          </div>
                        ) : (
                          <span className="muted" style={{ fontSize: 11 }}>No scans completed yet</span>
                        )}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        {totalFindings !== null ? (
                          <span style={{ fontWeight: 700 }}>{totalFindings}</span>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td>
                        <span
                          className="muted"
                          style={{ fontSize: 12 }}
                          title={new Date(project.created_at).toLocaleString()}
                        >
                          {relativeTime(project.created_at)}
                        </span>
                      </td>
                      <td onClick={(e) => e.stopPropagation()} style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                        <Link
                          href={`/projects/${project.id}`}
                          className="btn btn-ghost btn-sm"
                          style={{ marginRight: 4 }}
                        >
                          Manage →
                        </Link>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          title={`Delete project ${project.name}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            setProjectToDelete(project);
                          }}
                          style={{ color: "var(--danger)", padding: "4px 8px" }}
                        >
                          <TrashIcon width={13} height={13} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Floating Bulk Actions Toolbar ────────────────────────────── */}
      <BulkToolbar
        selectedCount={selectedIds.size}
        entityName="projects"
        onClearSelection={() => setSelectedIds(new Set())}
        onDeleteSelected={() => setShowBulkDeleteModal(true)}
        isDeleting={isBulkDeleting}
      />

      {/* ── Single Delete Confirmation Modal ──────────────────────────── */}
      <ConfirmModal
        isOpen={projectToDelete !== null}
        title="Delete Project?"
        message={`Are you sure you want to delete project "${projectToDelete?.name}"? All associated targets, scan runs, and discovered findings will be permanently deleted.`}
        confirmLabel="Delete Project"
        cancelLabel="Cancel"
        isDestructive
        isBusy={isDeletingSingle}
        onConfirm={executeSingleDelete}
        onCancel={() => setProjectToDelete(null)}
      />

      {/* ── Bulk Delete Confirmation Modal ───────────────────────────── */}
      <ConfirmModal
        isOpen={showBulkDeleteModal}
        title={`Delete ${selectedIds.size} Project${selectedIds.size > 1 ? "s" : ""}?`}
        message={`Are you sure you want to permanently delete the ${selectedIds.size} selected project(s)? All their scan histories, targets, and security findings will be removed.`}
        confirmLabel={`Delete ${selectedIds.size} Projects`}
        cancelLabel="Cancel"
        isDestructive
        isBusy={isBulkDeleting}
        onConfirm={executeBulkDelete}
        onCancel={() => setShowBulkDeleteModal(false)}
      />
    </div>
  );
}
