"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import React, { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import {
  api,
  isTerminal,
  type Project,
  type Scan,
  type SecurityScore,
  type Target,
  type TargetKind,
  type ToolName,
  type WorkspaceEntry,
} from "@/lib/api";
import Breadcrumb from "@/components/Breadcrumb";
import EmptyState from "@/components/EmptyState";
import StatusDot from "@/components/StatusDot";
import Tabs, { type TabItem } from "@/components/Tabs";
import HelpTrigger from "@/components/HelpTrigger";
import ConfirmModal from "@/components/ConfirmModal";
import {
  TargetIcon,
  ActivityIcon,
  PlayIcon,
  SearchIcon,
  GlobeIcon,
  CodeIcon,
  LayersIcon,
  ZapIcon,
  TrashIcon,
  ShieldIcon,
  AlertTriangleIcon,
  CheckIcon,
  ClockIcon,
  PlusIcon,
} from "@/components/icons";

/* ─── Tool Definitions & Meta ────────────────────────────────────────────── */

type SelectedTool = ToolName | "codebase_pipeline" | "recon_pipeline";
type ScannerCategory = "all" | "pipelines" | "code" | "dast";

type ToolMeta = {
  name: SelectedTool;
  label: string;
  category: "pipelines" | "code" | "dast";
  categoryTag: string;
  desc: string;
  icon: React.ReactNode;
  color: string;
  targetKinds: TargetKind[];
};

const TOOL_META: ToolMeta[] = [
  {
    name: "codebase_pipeline",
    label: "Full Codebase Audit",
    category: "pipelines",
    categoryTag: "PIPELINE",
    desc: "Unified Gitleaks, Semgrep, Trivy & Checkov pipeline",
    icon: <ShieldIcon width={14} height={14} />,
    color: "#388bfd",
    targetKinds: ["path"],
  },
  {
    name: "recon_pipeline",
    label: "Recon & DAST Pipeline",
    category: "pipelines",
    categoryTag: "PIPELINE",
    desc: "Subfinder ➔ HTTPx ➔ Nuclei automated attack surface discovery",
    icon: <ZapIcon width={14} height={14} />,
    color: "#e3b341",
    targetKinds: ["domain", "url"],
  },
  {
    name: "semgrep",
    label: "Semgrep",
    category: "code",
    categoryTag: "SAST",
    desc: "Static application security testing",
    icon: <CodeIcon width={14} height={14} />,
    color: "#3fb950",
    targetKinds: ["path"],
  },
  {
    name: "trivy",
    label: "Trivy",
    category: "code",
    categoryTag: "SCA / CVE",
    desc: "Dependency vulnerabilities & IaC misconfigurations",
    icon: <LayersIcon width={14} height={14} />,
    color: "#bc8cff",
    targetKinds: ["path"],
  },
  {
    name: "gitleaks",
    label: "Gitleaks",
    category: "code",
    categoryTag: "SECRETS",
    desc: "Hardcoded secret & API token detection",
    icon: <ShieldIcon width={14} height={14} />,
    color: "#f85149",
    targetKinds: ["path"],
  },
  {
    name: "checkov",
    label: "Checkov",
    category: "code",
    categoryTag: "IAC",
    desc: "Infrastructure-as-Code & Cloud security policies",
    icon: <ShieldIcon width={14} height={14} />,
    color: "#ff7b72",
    targetKinds: ["path"],
  },
  {
    name: "nuclei",
    label: "Nuclei",
    category: "dast",
    categoryTag: "DAST",
    desc: "Vulnerability & web application exploit scanner",
    icon: <ZapIcon width={14} height={14} />,
    color: "#d29922",
    targetKinds: ["url", "domain", "ip", "cidr"],
  },
  {
    name: "httpx",
    label: "HTTPx",
    category: "dast",
    categoryTag: "PROBE",
    desc: "Fast HTTP service, tech stack & port prober",
    icon: <GlobeIcon width={14} height={14} />,
    color: "#58a6ff",
    targetKinds: ["domain", "url", "ip", "cidr"],
  },
  {
    name: "subfinder",
    label: "Subfinder",
    category: "dast",
    categoryTag: "RECON",
    desc: "Passive subdomain & attack surface recon",
    icon: <SearchIcon width={14} height={14} />,
    color: "#388bfd",
    targetKinds: ["domain", "url"],
  },
];

const PATH_TOOLS: SelectedTool[] = ["codebase_pipeline", "semgrep", "trivy", "gitleaks", "checkov"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

const SEMGREP_RULESETS = [
  { value: "auto", label: "auto — AI-selected rules (Recommended)" },
  { value: "p/default", label: "p/default — Default ruleset" },
  { value: "p/owasp-top-ten", label: "p/owasp-top-ten — OWASP Top 10" },
  { value: "p/cwe-top-25", label: "p/cwe-top-25 — CWE Top 25" },
  { value: "p/secrets", label: "p/secrets — Secret detection" },
  { value: "p/python", label: "p/python — Python specific" },
  { value: "p/javascript", label: "p/javascript — JavaScript / Node.js" },
  { value: "p/typescript", label: "p/typescript — TypeScript" },
];

const TRIVY_SCANNERS = [
  { value: "vuln", label: "vuln", desc: "CVE vulnerability scanning" },
  { value: "secret", label: "secret", desc: "Hardcoded API keys & tokens" },
  { value: "misconfig", label: "misconfig", desc: "IaC misconfiguration" },
  { value: "license", label: "license", desc: "License compliance" },
];

const TARGET_KIND_ICONS: Record<TargetKind, React.ReactNode> = {
  url: <GlobeIcon width={13} height={13} />,
  domain: <GlobeIcon width={13} height={13} />,
  ip: <TargetIcon width={13} height={13} />,
  cidr: <TargetIcon width={13} height={13} />,
  path: <CodeIcon width={13} height={13} />,
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

function duration(start: string | null, end: string | null): string {
  if (!start) return "—";
  const endMs = end ? new Date(end).getTime() : Date.now();
  const secs = Math.max(0, Math.round((endMs - new Date(start).getTime()) / 1000));
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}m ${s}s`;
}

type TabType = "scans" | "targets";

export default function ProjectPage() {
  const params = useParams<{ id: string }>();
  const projectId = params.id;
  const router = useRouter();

  const [activeTab, setActiveTab] = useState<TabType>("scans");
  const [project, setProject] = useState<Project | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [securityScore, setSecurityScore] = useState<SecurityScore | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [batchSuccess, setBatchSuccess] = useState<string | null>(null);

  // Modals for confirmation
  const [showDeleteProjectModal, setShowDeleteProjectModal] = useState(false);
  const [isDeletingProject, setIsDeletingProject] = useState(false);

  const [targetToDelete, setTargetToDelete] = useState<Target | null>(null);
  const [isDeletingTarget, setIsDeletingTarget] = useState(false);

  const [scanToDelete, setScanToDelete] = useState<Scan | null>(null);
  const [isDeletingScan, setIsDeletingScan] = useState(false);

  // Target add form
  const [targetKind, setTargetKind] = useState<TargetKind>("url");
  const [targetValue, setTargetValue] = useState("");
  const [pathMode, setPathMode] = useState<"custom" | "workspace">("custom");
  const [workspaceEntries, setWorkspaceEntries] = useState<WorkspaceEntry[] | null>(null);
  const [workspaceRoot, setWorkspaceRoot] = useState<string>("");
  const [addingTarget, setAddingTarget] = useState(false);

  // Scan launcher state
  const [tool, setTool] = useState<SelectedTool>("codebase_pipeline");
  const [scannerCategory, setScannerCategory] = useState<ScannerCategory>("all");
  const [scanTargetId, setScanTargetId] = useState("");
  const [startingScans, setStartingScans] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Pipeline stages config
  const [suiteTools, setSuiteTools] = useState<ToolName[]>(["gitleaks", "semgrep", "trivy", "checkov"]);

  // Nuclei config
  const [severities, setSeverities] = useState<string[]>(["high", "critical"]);
  const [nucleiHeaders, setNucleiHeaders] = useState("");
  const [nucleiExcludeTags, setNucleiExcludeTags] = useState("");
  const [nucleiRestrictLocal, setNucleiRestrictLocal] = useState(false);
  const [nucleiStopAtFirstMatch, setNucleiStopAtFirstMatch] = useState(false);

  // Semgrep config
  const [semgrepConfig, setSemgrepConfig] = useState("auto");
  const [semgrepCustom, setSemgrepCustom] = useState("");

  // Trivy config
  const [trivyScanners, setTrivyScanners] = useState<string[]>(["vuln", "secret", "misconfig"]);
  const [trivySkipDb, setTrivySkipDb] = useState(false);
  const [trivyOffline, setTrivyOffline] = useState(false);

  // Gitleaks config
  const [gitleaksNoGit, setGitleaksNoGit] = useState(false);
  const [gitleaksRedact, setGitleaksRedact] = useState(false);

  // Checkov config
  const [checkovFramework, setCheckovFramework] = useState("all");

  // HTTPx config
  const [httpxTechDetect, setHttpxTechDetect] = useState(true);
  const [httpxFollowRedirects, setHttpxFollowRedirects] = useState(false);
  const [httpxPorts, setHttpxPorts] = useState("");
  const [httpxPath, setHttpxPath] = useState("");

  /* ── Load Data ───────────────────────────────────────────────────────── */

  const load = useCallback(async () => {
    try {
      const [projectData, targetsData, scansData, scoreData] = await Promise.all([
        api.getProject(projectId),
        api.listTargets(projectId),
        api.listScans(projectId),
        api.getProjectSecurityScore(projectId).catch(() => null),
      ]);
      setProject(projectData);
      setTargets(targetsData);
      setScans(scansData);
      setSecurityScore(scoreData);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load project details");
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    void load();
  }, [load]);

  // Live polling while active scans are in progress
  useEffect(() => {
    const hasActive = scans.some((s) => !isTerminal(s.status));
    if (!hasActive) return;
    const interval = setInterval(() => void load(), 3000);
    return () => clearInterval(interval);
  }, [scans, load]);

  // Load workspace entries when needed
  useEffect(() => {
    const needsWorkspace = targetKind === "path" || PATH_TOOLS.includes(tool);
    if (!needsWorkspace || workspaceEntries !== null) return;
    void api.getWorkspace()
      .then((ws) => {
        setWorkspaceEntries(ws.available ? ws.entries : []);
        setWorkspaceRoot(ws.root);
      })
      .catch(() => {
        setWorkspaceEntries([]);
      });
  }, [targetKind, tool, workspaceEntries]);

  /* ── Target Eligibility Helper ────────────────────────────────────────── */

  const isPathTool = PATH_TOOLS.includes(tool);
  const eligibleTargets = useMemo(() => {
    return targets.filter((t) => {
      if (!t.is_active) return false;
      return isPathTool ? t.kind === "path" : t.kind !== "path";
    });
  }, [targets, isPathTool]);

  const selectedTargetEligible = eligibleTargets.some((t) => t.id === scanTargetId);
  const selectedToolMeta = TOOL_META.find((t) => t.name === tool);
  const canSubmitScan = !!scanTargetId && selectedTargetEligible && !startingScans;

  /* ── Actions ──────────────────────────────────────────────────────────── */

  async function handleAddTarget(e: FormEvent) {
    e.preventDefault();
    if (!targetValue.trim()) return;
    setAddingTarget(true);
    setError(null);
    try {
      await api.addTarget(projectId, { kind: targetKind, value: targetValue.trim() });
      setTargetValue("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add target");
    } finally {
      setAddingTarget(false);
    }
  }

  async function executeDeleteTarget() {
    if (!targetToDelete) return;
    setIsDeletingTarget(true);
    setError(null);
    try {
      await api.deleteTarget(projectId, targetToDelete.id);
      if (scanTargetId === targetToDelete.id) setScanTargetId("");
      setTargetToDelete(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete target");
    } finally {
      setIsDeletingTarget(false);
    }
  }

  async function executeDeleteScan() {
    if (!scanToDelete) return;
    setIsDeletingScan(true);
    setError(null);
    try {
      await api.deleteScan(scanToDelete.id);
      setScanToDelete(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete scan");
    } finally {
      setIsDeletingScan(false);
    }
  }

  async function executeDeleteProject() {
    if (!project) return;
    setIsDeletingProject(true);
    setError(null);
    try {
      await api.deleteProject(projectId);
      router.push("/projects");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete project");
      setIsDeletingProject(false);
    }
  }

  async function handleStartScan(e: FormEvent) {
    e.preventDefault();
    setStartingScans(true);
    setError(null);
    setBatchSuccess(null);

    if (tool === "codebase_pipeline") {
      if (suiteTools.length === 0) {
        setError("Please select at least one engine for the Full Codebase Audit pipeline.");
        setStartingScans(false);
        return;
      }
      try {
        const res = await api.startCodebasePipeline(projectId, {
          target_id: scanTargetId || undefined,
          tools: suiteTools,
        });
        setBatchSuccess(
          `Full Codebase Audit started! (Pipeline ID: ${res.pipeline_id.slice(0, 8)}). ${suiteTools.join(", ")} are running.`
        );
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to start codebase audit pipeline");
      } finally {
        setStartingScans(false);
      }
      return;
    }

    if (tool === "recon_pipeline") {
      try {
        const res = await api.startReconPipeline(projectId, {
          target_id: scanTargetId || undefined,
          nuclei_severity: severities as import("@/lib/api").Severity[],
        });
        setBatchSuccess(`Recon & DAST Pipeline started! (Pipeline ID: ${res.pipeline_id.slice(0, 8)}). Subfinder, HTTPx, and Nuclei will run sequentially.`);
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to start recon pipeline");
      } finally {
        setStartingScans(false);
      }
      return;
    }

    let config: Record<string, unknown> | undefined;
    if (tool === "nuclei") {
      const parsedHeaders = nucleiHeaders
        .split("\n")
        .map((h) => h.trim())
        .filter((h) => h.includes(":"));
      const parsedExcludeTags = nucleiExcludeTags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);

      config = {
        ...(severities.length > 0 ? { severity: severities } : {}),
        ...(parsedHeaders.length > 0 ? { custom_headers: parsedHeaders } : {}),
        ...(parsedExcludeTags.length > 0 ? { exclude_tags: parsedExcludeTags } : {}),
        ...(nucleiRestrictLocal ? { restrict_local_network: true } : {}),
        ...(nucleiStopAtFirstMatch ? { stop_at_first_match: true } : {}),
      };
    } else if (tool === "semgrep") {
      const rules = semgrepConfig === "custom" ? semgrepCustom.trim() : semgrepConfig;
      config = { config: rules };
    } else if (tool === "trivy") {
      config = {
        scanners: trivyScanners,
        ...(trivySkipDb ? { skip_db_update: true } : {}),
        ...(trivyOffline ? { offline_scan: true } : {}),
      };
    } else if (tool === "gitleaks") {
      config = {
        ...(gitleaksNoGit ? { no_git: true } : {}),
        ...(gitleaksRedact ? { redact: true } : {}),
      };
    } else if (tool === "checkov") {
      config = {
        framework: checkovFramework,
      };
    } else if (tool === "httpx") {
      const parsedPorts = httpxPorts
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean);
      config = {
        tech_detect: httpxTechDetect,
        ...(httpxFollowRedirects ? { follow_redirects: true } : {}),
        ...(parsedPorts.length > 0 ? { ports: parsedPorts } : {}),
        ...(httpxPath.trim() ? { path: httpxPath.trim() } : {}),
      };
    }

    try {
      const createdScan = await api.startScan(projectId, {
        tool,
        target_id: scanTargetId || undefined,
        config,
      });
      router.push(`/scans/${createdScan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setStartingScans(false);
    }
  }

  function toggleSuiteTool(t: ToolName) {
    setSuiteTools((curr) =>
      curr.includes(t) ? curr.filter((item) => item !== t) : [...curr, t]
    );
  }

  function toggleSeverity(sev: string) {
    setSeverities((c) => (c.includes(sev) ? c.filter((s) => s !== sev) : [...c, sev]));
  }

  function toggleTrivyScanner(scanner: string) {
    setTrivyScanners((c) =>
      c.includes(scanner) ? c.filter((s) => s !== scanner) : [...c, scanner]
    );
  }

  /* ── Tab Items ────────────────────────────────────────────────────────── */

  const tabItems: TabItem<TabType>[] = [
    {
      id: "scans",
      label: "Scans & Audit",
      icon: <ActivityIcon width={14} height={14} />,
      count: scans.length,
    },
    {
      id: "targets",
      label: "Targets & Scope",
      icon: <TargetIcon width={14} height={14} />,
      count: targets.length,
    },
  ];

  /* ── Total Findings across project scans ─────────────────────────────── */
  const totalFindings = scans.reduce((sum, s) => sum + (s.stats?.findings ?? 0), 0);
  const criticalFindings = scans.reduce((sum, s) => sum + (s.stats?.by_severity?.["critical"] ?? 0), 0);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* ── Breadcrumb ──────────────────────────────────────────────── */}
      <Breadcrumb
        items={[
          { label: "Projects", href: "/projects" },
          { label: project?.name ?? "Project" },
        ]}
      />

      {/* ── Project Header ─────────────────────────────────────────── */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div className="page-title-group">
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <h1>{project?.name ?? "Loading project…"}</h1>
            {criticalFindings > 0 && (
              <span className="badge critical">{criticalFindings} crit</span>
            )}
          </div>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            {project?.description || "No description set"} · {targets.length} target{targets.length !== 1 ? "s" : ""} · {totalFindings} total findings
          </p>
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            style={{ color: "var(--danger)", borderColor: "rgba(248,81,73,0.3)" }}
            onClick={() => setShowDeleteProjectModal(true)}
            disabled={!project}
          >
            <TrashIcon width={13} height={13} />
            Delete project
          </button>
        </div>
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

      {batchSuccess && (
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
            {batchSuccess}
          </span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => setBatchSuccess(null)}
            style={{ color: "var(--success)", padding: "2px 6px" }}
          >
            ✕
          </button>
        </div>
      )}

      {/* ── Tabs Navigation ─────────────────────────────────────────── */}
      <Tabs
        tabs={tabItems}
        activeTab={activeTab}
        onChange={(tab) => setActiveTab(tab)}
      />

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* ── TAB 1: SCANS & AUDIT ───────────────────────────────────────── */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      {activeTab === "scans" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {/* ── Security Posture & Score Card ─────────────────────────── */}
          {securityScore && (
            <div
              className="card"
              style={{
                padding: "20px 24px",
                background: "linear-gradient(135deg, var(--panel) 0%, rgba(56, 139, 253, 0.04) 100%)",
                border: "1px solid var(--border)",
              }}
            >
              <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: 20 }}>
                {/* Left: Score & Grade */}
                <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
                  <div
                    style={{
                      width: 68,
                      height: 68,
                      borderRadius: "50%",
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      justifyContent: "center",
                      background:
                        securityScore.grade === "A"
                          ? "rgba(63, 185, 80, 0.15)"
                          : securityScore.grade === "B"
                          ? "rgba(88, 166, 255, 0.15)"
                          : securityScore.grade === "C"
                          ? "rgba(210, 153, 34, 0.15)"
                          : securityScore.grade === "D"
                          ? "rgba(219, 109, 40, 0.15)"
                          : "rgba(248, 81, 73, 0.15)",
                      border: `3px solid ${
                        securityScore.grade === "A"
                          ? "#3fb950"
                          : securityScore.grade === "B"
                          ? "#58a6ff"
                          : securityScore.grade === "C"
                          ? "#d29922"
                          : securityScore.grade === "D"
                          ? "#db6d28"
                          : "#f85149"
                      }`,
                    }}
                  >
                    <span style={{ fontSize: 22, fontWeight: 800, lineHeight: 1 }}>{securityScore.grade}</span>
                    <span style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>{securityScore.score}/100</span>
                  </div>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <h2 style={{ margin: 0, fontSize: 16 }}>Unified Security Posture Score</h2>
                      <span className={`badge ${securityScore.grade === "A" || securityScore.grade === "B" ? "success" : securityScore.grade === "C" ? "medium" : "critical"}`}>
                        Grade {securityScore.grade} ({securityScore.score} pts)
                      </span>
                    </div>
                    <p className="muted" style={{ margin: "4px 0 0", fontSize: 12 }}>
                      {securityScore.total_findings === 0
                        ? "Clean codebase — no active security vulnerabilities detected"
                        : `${securityScore.total_findings} total findings (-${securityScore.penalties} penalty points across scanned tools)`}
                    </p>
                  </div>
                </div>

                {/* Right: Quick Action */}
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => {
                    setTool("codebase_pipeline");
                    const pathTarget = targets.find((t) => t.kind === "path");
                    if (pathTarget) setScanTargetId(pathTarget.id);
                  }}
                  style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
                >
                  <ShieldIcon width={13} height={13} />
                  Run Full Codebase Audit
                </button>
              </div>

              {/* Category Breakdown */}
              {Object.keys(securityScore.categories).length > 0 && (
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
                    gap: 10,
                    marginTop: 16,
                    paddingTop: 16,
                    borderTop: "1px solid var(--border)",
                  }}
                >
                  {Object.entries(securityScore.categories).map(([catKey, cat]) => {
                    const catColor =
                      cat.grade === "A"
                        ? "#3fb950"
                        : cat.grade === "B"
                        ? "#58a6ff"
                        : cat.grade === "C"
                        ? "#d29922"
                        : cat.grade === "D"
                        ? "#db6d28"
                        : "#f85149";
                    return (
                      <div
                        key={catKey}
                        style={{
                          padding: "8px 10px",
                          borderRadius: "var(--radius-sm)",
                          background: "var(--panel)",
                          border: "1px solid var(--border)",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", color: "var(--text-muted)" }}>
                            {catKey}
                          </span>
                          <span
                            style={{
                              fontSize: 10,
                              fontWeight: 700,
                              color: catColor,
                              padding: "1px 4px",
                              borderRadius: 3,
                              background: `${catColor}20`,
                            }}
                          >
                            {cat.grade} ({cat.score})
                          </span>
                        </div>
                        <div style={{ fontSize: 12, fontWeight: 600, marginTop: 4 }}>
                          {cat.total_findings} finding{cat.total_findings !== 1 ? "s" : ""}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* ── Scan Launcher Panel ────────────────────────────────────── */}
          <div className="card">
            <div className="card-header">
              <h2 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0 }}>
                <PlayIcon width={15} height={15} style={{ color: "var(--accent-hover)" }} />
                Launch Security Scan
              </h2>
            </div>

            <form onSubmit={handleStartScan} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {/* Enterprise Scanner Engine Selector */}
              <div className="engine-selector-wrap">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
                  <label style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--text-muted)" }}>
                    Security Engine & Mode
                  </label>

                  {/* Category Pills */}
                  <div className="engine-categories">
                    <button
                      type="button"
                      className={`engine-cat-btn${scannerCategory === "all" ? " active" : ""}`}
                      onClick={() => setScannerCategory("all")}
                    >
                      All ({TOOL_META.length})
                    </button>
                    <button
                      type="button"
                      className={`engine-cat-btn${scannerCategory === "pipelines" ? " active" : ""}`}
                      onClick={() => setScannerCategory("pipelines")}
                    >
                      ⚡ Pipelines ({TOOL_META.filter((t) => t.category === "pipelines").length})
                    </button>
                    <button
                      type="button"
                      className={`engine-cat-btn${scannerCategory === "code" ? " active" : ""}`}
                      onClick={() => setScannerCategory("code")}
                    >
                      🔍 Code & IaC ({TOOL_META.filter((t) => t.category === "code").length})
                    </button>
                    <button
                      type="button"
                      className={`engine-cat-btn${scannerCategory === "dast" ? " active" : ""}`}
                      onClick={() => setScannerCategory("dast")}
                    >
                      🌐 DAST & Recon ({TOOL_META.filter((t) => t.category === "dast").length})
                    </button>
                  </div>
                </div>

                {/* Compact Engine Grid */}
                <div className="engine-grid">
                  {TOOL_META.filter((t) => scannerCategory === "all" || t.category === scannerCategory).map((t) => {
                    const isSelected = tool === t.name;
                    return (
                      <button
                        key={t.name}
                        type="button"
                        className={`engine-row-btn${isSelected ? " selected" : ""}`}
                        onClick={() => {
                          setTool(t.name);
                          setScanTargetId("");
                        }}
                      >
                        <div className="engine-row-left">
                          <div className="engine-row-icon" style={{ background: `${t.color}20`, color: t.color }}>
                            {t.icon}
                          </div>
                          <span className="engine-row-title">{t.label}</span>
                        </div>
                        <span className="engine-row-tag">{t.categoryTag}</span>
                      </button>
                    );
                  })}
                </div>

                {/* Selected Engine Summary Strip */}
                {selectedToolMeta && (
                  <div className="engine-summary-bar">
                    <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                      <span style={{ color: selectedToolMeta.color, display: "flex", alignItems: "center" }}>
                        {selectedToolMeta.icon}
                      </span>
                      <span style={{ fontWeight: 600, color: "var(--text)" }}>{selectedToolMeta.label}:</span>
                      <span className="muted" style={{ fontSize: 12 }}>{selectedToolMeta.desc}</span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
                      <span className="muted" style={{ fontSize: 11 }}>Target:</span>
                      <span
                        className="badge"
                        style={{
                          fontSize: 10,
                          padding: "1px 6px",
                          background: isPathTool ? "rgba(188,140,255,0.12)" : "rgba(56,139,253,0.12)",
                          color: isPathTool ? "#bc8cff" : "#58a6ff",
                          border: `1px solid ${isPathTool ? "rgba(188,140,255,0.25)" : "rgba(56,139,253,0.25)"}`,
                        }}
                      >
                        {isPathTool ? "📁 Local Path (SAST)" : "🌐 Web / Network Target"}
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Target Selector */}
              <div className="field">
                <label htmlFor="scan-target">
                  Target Scope *
                  {isPathTool && (
                    <span className="muted" style={{ fontWeight: 400, marginLeft: 6, fontSize: 11 }}>
                      (requires a <code>path</code> target)
                    </span>
                  )}
                </label>

                {eligibleTargets.length === 0 ? (
                  <div
                    style={{
                      padding: "12px 14px",
                      borderRadius: "var(--radius-md)",
                      border: "1px dashed var(--border)",
                      fontSize: 13,
                      color: "var(--text-subtle)",
                      background: "var(--bg-subtle)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                    }}
                  >
                    <span>
                      {isPathTool
                        ? "No local directory targets added yet."
                        : `No compatible network targets for ${selectedToolMeta?.label}.`}
                    </span>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => setActiveTab("targets")}
                    >
                      + Add Target
                    </button>
                  </div>
                ) : (
                  <select
                    id="scan-target"
                    value={scanTargetId}
                    onChange={(e) => setScanTargetId(e.target.value)}
                    required
                  >
                    <option value="">Select a target to scan…</option>
                    {eligibleTargets.map((target) => (
                      <option key={target.id} value={target.id}>
                        [{target.kind}] {target.value}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* Full Codebase Audit Pipeline Stage Customization */}
              {tool === "codebase_pipeline" && (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                    padding: "12px 14px",
                    borderRadius: "var(--radius-md)",
                    background: "var(--bg-subtle)",
                    border: "1px solid var(--border)",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text)" }}>
                      Included Audit Stages ({suiteTools.length}/4 active):
                    </span>
                    <span className="muted" style={{ fontSize: 11 }}>
                      Engines will run sequentially in a unified audit session
                    </span>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 8 }}>
                    <label
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        cursor: "pointer",
                        padding: "6px 10px",
                        borderRadius: "var(--radius-sm)",
                        border: `1px solid ${suiteTools.includes("gitleaks") ? "rgba(248,81,73,0.4)" : "var(--border)"}`,
                        background: suiteTools.includes("gitleaks") ? "rgba(248,81,73,0.08)" : "var(--panel)",
                        fontSize: 12,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={suiteTools.includes("gitleaks")}
                        onChange={() => toggleSuiteTool("gitleaks")}
                        style={{ accentColor: "#f85149" }}
                      />
                      <span style={{ fontWeight: 600, color: "#f85149" }}>Gitleaks</span>
                      <span className="muted" style={{ fontSize: 10, marginLeft: "auto" }}>Secrets</span>
                    </label>

                    <label
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        cursor: "pointer",
                        padding: "6px 10px",
                        borderRadius: "var(--radius-sm)",
                        border: `1px solid ${suiteTools.includes("semgrep") ? "rgba(63,185,80,0.4)" : "var(--border)"}`,
                        background: suiteTools.includes("semgrep") ? "rgba(63,185,80,0.08)" : "var(--panel)",
                        fontSize: 12,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={suiteTools.includes("semgrep")}
                        onChange={() => toggleSuiteTool("semgrep")}
                        style={{ accentColor: "#3fb950" }}
                      />
                      <span style={{ fontWeight: 600, color: "#3fb950" }}>Semgrep</span>
                      <span className="muted" style={{ fontSize: 10, marginLeft: "auto" }}>SAST</span>
                    </label>

                    <label
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        cursor: "pointer",
                        padding: "6px 10px",
                        borderRadius: "var(--radius-sm)",
                        border: `1px solid ${suiteTools.includes("trivy") ? "rgba(188,140,255,0.4)" : "var(--border)"}`,
                        background: suiteTools.includes("trivy") ? "rgba(188,140,255,0.08)" : "var(--panel)",
                        fontSize: 12,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={suiteTools.includes("trivy")}
                        onChange={() => toggleSuiteTool("trivy")}
                        style={{ accentColor: "#bc8cff" }}
                      />
                      <span style={{ fontWeight: 600, color: "#bc8cff" }}>Trivy</span>
                      <span className="muted" style={{ fontSize: 10, marginLeft: "auto" }}>SCA</span>
                    </label>

                    <label
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        cursor: "pointer",
                        padding: "6px 10px",
                        borderRadius: "var(--radius-sm)",
                        border: `1px solid ${suiteTools.includes("checkov") ? "rgba(255,123,114,0.4)" : "var(--border)"}`,
                        background: suiteTools.includes("checkov") ? "rgba(255,123,114,0.08)" : "var(--panel)",
                        fontSize: 12,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={suiteTools.includes("checkov")}
                        onChange={() => toggleSuiteTool("checkov")}
                        style={{ accentColor: "#ff7b72" }}
                      />
                      <span style={{ fontWeight: 600, color: "#ff7b72" }}>Checkov</span>
                      <span className="muted" style={{ fontSize: 10, marginLeft: "auto" }}>IaC</span>
                    </label>
                  </div>
                </div>
              )}

              {/* Progressive Disclosure Toggle */}
              {tool !== "subfinder" && (
                <div>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={() => setShowAdvanced((v) => !v)}
                    style={{ fontSize: 12, padding: "2px 6px" }}
                  >
                    {showAdvanced ? "▾ Hide advanced options" : "▸ Show advanced options"}
                  </button>
                </div>
              )}

              {/* Advanced Collapsible Section */}
              {showAdvanced && (
                <div
                  style={{
                    padding: 16,
                    borderRadius: "var(--radius-md)",
                    background: "var(--bg-subtle)",
                    border: "1px solid var(--border)",
                    display: "flex",
                    flexDirection: "column",
                    gap: 14,
                  }}
                >
                  {/* Nuclei Advanced Options */}
                  {tool === "nuclei" && (
                    <>
                      <div className="field">
                        <div className="field-label">Severity Filter</div>
                        <div className="checkbox-row">
                          {SEVERITIES.map((sev) => (
                            <label
                              key={sev}
                              className={`checkbox-chip ${sev}${severities.includes(sev) ? " checked" : ""}`}
                            >
                              <input
                                type="checkbox"
                                checked={severities.includes(sev)}
                                onChange={() => toggleSeverity(sev)}
                              />
                              {sev}
                            </label>
                          ))}
                        </div>
                      </div>

                      <div className="field">
                        <label htmlFor="nuclei-headers">
                          Custom Headers <span className="muted">(e.g. Authorization: Bearer token)</span>
                        </label>
                        <textarea
                          id="nuclei-headers"
                          rows={2}
                          value={nucleiHeaders}
                          onChange={(e) => setNucleiHeaders(e.target.value)}
                          placeholder="Authorization: Bearer token"
                          style={{ fontFamily: "monospace", fontSize: 12 }}
                        />
                      </div>

                      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 13 }}>
                          <input
                            type="checkbox"
                            checked={nucleiRestrictLocal}
                            onChange={(e) => setNucleiRestrictLocal(e.target.checked)}
                          />
                          Restrict local network scan (-lna)
                        </label>
                        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 13 }}>
                          <input
                            type="checkbox"
                            checked={nucleiStopAtFirstMatch}
                            onChange={(e) => setNucleiStopAtFirstMatch(e.target.checked)}
                          />
                          Stop at first match (-sfm)
                        </label>
                      </div>
                    </>
                  )}

                  {/* Semgrep Options */}
                  {(tool === "semgrep" || (tool === "codebase_pipeline" && suiteTools.includes("semgrep"))) && (
                    <div className="field">
                      <label htmlFor="semgrep-rule-select">
                        Semgrep Ruleset
                        <HelpTrigger
                          title="Semgrep Presets"
                          content={<p>Choose AI auto-detection or OWASP Top 10 rulesets for code analysis.</p>}
                        />
                      </label>
                      <select
                        id="semgrep-rule-select"
                        value={semgrepConfig}
                        onChange={(e) => setSemgrepConfig(e.target.value)}
                      >
                        {SEMGREP_RULESETS.map((r) => (
                          <option key={r.value} value={r.value}>{r.label}</option>
                        ))}
                      </select>
                    </div>
                  )}

                  {/* Trivy Options */}
                  {(tool === "trivy" || (tool === "codebase_pipeline" && suiteTools.includes("trivy"))) && (
                    <div className="field">
                      <div className="field-label">Trivy Scanners</div>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        {TRIVY_SCANNERS.map((s) => (
                          <label
                            key={s.value}
                            className={`checkbox-chip ${trivyScanners.includes(s.value) ? " checked" : ""}`}
                          >
                            <input
                              type="checkbox"
                              checked={trivyScanners.includes(s.value)}
                              onChange={() => toggleTrivyScanner(s.value)}
                            />
                            {s.label}
                          </label>
                        ))}
                      </div>
                      <div style={{ display: "flex", gap: 16, marginTop: 8 }}>
                        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 12 }}>
                          <input
                            type="checkbox"
                            checked={trivySkipDb}
                            onChange={(e) => setTrivySkipDb(e.target.checked)}
                          />
                          Skip DB update (faster)
                        </label>
                        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 12 }}>
                          <input
                            type="checkbox"
                            checked={trivyOffline}
                            onChange={(e) => setTrivyOffline(e.target.checked)}
                          />
                          Offline scan
                        </label>
                      </div>
                    </div>
                  )}

                  {/* Gitleaks Options */}
                  {(tool === "gitleaks" || (tool === "codebase_pipeline" && suiteTools.includes("gitleaks"))) && (
                    <div style={{ display: "flex", gap: 16 }}>
                      <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 13 }}>
                        <input
                          type="checkbox"
                          checked={gitleaksNoGit}
                          onChange={(e) => setGitleaksNoGit(e.target.checked)}
                        />
                        No Git history (scan files directly)
                      </label>
                      <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 13 }}>
                        <input
                          type="checkbox"
                          checked={gitleaksRedact}
                          onChange={(e) => setGitleaksRedact(e.target.checked)}
                        />
                        Redact matched secrets
                      </label>
                    </div>
                  )}

                  {/* Checkov Options */}
                  {(tool === "checkov" || (tool === "codebase_pipeline" && suiteTools.includes("checkov"))) && (
                    <div className="field">
                      <label htmlFor="checkov-framework-select">
                        Checkov Framework
                        <HelpTrigger
                          title="IaC Framework"
                          content={<p>Select the specific framework (e.g. Terraform, CloudFormation, Kubernetes, Dockerfile) or leave as 'all'.</p>}
                        />
                      </label>
                      <select
                        id="checkov-framework-select"
                        value={checkovFramework}
                        onChange={(e) => setCheckovFramework(e.target.value)}
                      >
                        <option value="all">all — Auto-detect all IaC frameworks</option>
                        <option value="terraform">terraform — Terraform (.tf)</option>
                        <option value="cloudformation">cloudformation — AWS CloudFormation</option>
                        <option value="kubernetes">kubernetes — Kubernetes manifests</option>
                        <option value="dockerfile">dockerfile — Dockerfiles</option>
                        <option value="github_actions">github_actions — GitHub Actions workflows</option>
                        <option value="ansible">ansible — Ansible playbooks</option>
                      </select>
                    </div>
                  )}

                  {/* HTTPx Options */}
                  {tool === "httpx" && (
                    <>
                      <div style={{ display: "flex", gap: 16 }}>
                        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 13 }}>
                          <input
                            type="checkbox"
                            checked={httpxTechDetect}
                            onChange={(e) => setHttpxTechDetect(e.target.checked)}
                          />
                          Technology Detection (-td)
                        </label>
                        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 13 }}>
                          <input
                            type="checkbox"
                            checked={httpxFollowRedirects}
                            onChange={(e) => setHttpxFollowRedirects(e.target.checked)}
                          />
                          Follow Redirects (-fr)
                        </label>
                      </div>

                      <div className="field">
                        <label htmlFor="httpx-ports">
                          Probe Specific Ports <span className="muted">(comma-separated, e.g. 80,443,8080,8443)</span>
                        </label>
                        <input
                          id="httpx-ports"
                          type="text"
                          value={httpxPorts}
                          onChange={(e) => setHttpxPorts(e.target.value)}
                          placeholder="e.g. 80,443,8080,8443"
                        />
                      </div>

                      <div className="field">
                        <label htmlFor="httpx-path">
                          Custom Path <span className="muted">(e.g. /api/v1/health or /login)</span>
                        </label>
                        <input
                          id="httpx-path"
                          type="text"
                          value={httpxPath}
                          onChange={(e) => setHttpxPath(e.target.value)}
                          placeholder="/api/v1"
                        />
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* Action Submit Button */}
              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={!canSubmitScan}
                >
                  <PlayIcon width={14} height={14} />
                  {startingScans
                    ? "Launching scan…"
                    : tool === "codebase_pipeline"
                    ? `Run Full Codebase Audit (${suiteTools.length} engines)`
                    : tool === "recon_pipeline"
                    ? "Run Recon & DAST Pipeline (Subfinder ➔ HTTPx ➔ Nuclei)"
                    : `Start ${selectedToolMeta?.label} Scan`}
                </button>
              </div>
            </form>
          </div>

          {/* ── Scan History Table ─────────────────────────────────────── */}
          <div className="card" style={{ padding: 0, overflow: "hidden" }}>
            <div className="card-header" style={{ padding: "18px 20px" }}>
              <h2 style={{ margin: 0, fontSize: 15 }}>Project Scan History</h2>
            </div>

            {loading ? (
              <div style={{ padding: 32 }}>
                {[1, 2, 3].map((i) => (
                  <div key={i} className="skeleton" style={{ height: 40, borderRadius: 6, marginBottom: 8 }} />
                ))}
              </div>
            ) : scans.length === 0 ? (
              <EmptyState
                icon={<ActivityIcon />}
                title="No scans executed for this project yet"
                description="Select an engine above and click Launch Security Scan."
              />
            ) : (
              <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Tool</th>
                      <th>Target</th>
                      <th>Findings</th>
                      <th>Duration</th>
                      <th>Started</th>
                      <th style={{ textAlign: "right" }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((scan) => (
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
                          <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, fontWeight: 600 }}>
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
                            {duration(scan.started_at, scan.finished_at)}
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
                            onClick={(e) => {
                              e.stopPropagation();
                              setScanToDelete(scan);
                            }}
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
            )}
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* ── TAB 2: TARGETS & SCOPE ─────────────────────────────────────── */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      {activeTab === "targets" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {/* ── Add Target Card ────────────────────────────────────────── */}
          <div className="card">
            <div className="card-header">
              <h2 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0 }}>
                <PlusIcon width={15} height={15} style={{ color: "var(--accent-hover)" }} />
                Add Target Scope
              </h2>
            </div>

            <form onSubmit={handleAddTarget} className="form-row">
              <div className="field" style={{ minWidth: 140 }}>
                <label htmlFor="kind">Kind</label>
                <select
                  id="kind"
                  value={targetKind}
                  onChange={(e) => {
                    setTargetKind(e.target.value as TargetKind);
                    setTargetValue("");
                  }}
                >
                  <option value="url">URL (Web target)</option>
                  <option value="domain">Domain (Host)</option>
                  <option value="ip">IP Address</option>
                  <option value="cidr">CIDR Subnet</option>
                  <option value="path">Local Path / Workspace</option>
                </select>
              </div>

              {targetKind === "path" ? (
                <div className="field" style={{ flex: 1, minWidth: 240 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                    <label htmlFor="path-value" style={{ margin: 0 }}>
                      Directory Path *
                    </label>
                    {workspaceEntries && workspaceEntries.length > 0 && (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => {
                          setPathMode((m) => (m === "workspace" ? "custom" : "workspace"));
                          setTargetValue("");
                        }}
                        style={{ fontSize: 11, padding: "1px 6px" }}
                      >
                        {pathMode === "workspace" ? "✏️ Enter custom path" : "📂 Pick from workspace"}
                      </button>
                    )}
                  </div>
                  {pathMode === "workspace" && workspaceEntries && workspaceEntries.length > 0 ? (
                    <select
                      id="path-value"
                      value={targetValue}
                      onChange={(e) => setTargetValue(e.target.value)}
                      required
                    >
                      <option value="">Select a directory from workspace…</option>
                      {workspaceEntries.map((entry) => (
                        <option key={entry.path} value={entry.path}>
                          {entry.name} {workspaceRoot ? `(${workspaceRoot}/${entry.path})` : ""}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      id="path-value"
                      value={targetValue}
                      onChange={(e) => setTargetValue(e.target.value)}
                      placeholder="/home/user/project or repo-folder"
                      required
                    />
                  )}
                </div>
              ) : (
                <div className="field" style={{ flex: 1, minWidth: 240 }}>
                  <label htmlFor="target-value">Target Value *</label>
                  <input
                    id="target-value"
                    value={targetValue}
                    onChange={(e) => setTargetValue(e.target.value)}
                    placeholder={
                      targetKind === "domain"
                        ? "example.com"
                        : targetKind === "ip"
                        ? "192.168.1.1"
                        : targetKind === "cidr"
                        ? "192.168.1.0/24"
                        : "https://example.com"
                    }
                    required
                  />
                </div>
              )}

              <div className="field" style={{ justifyContent: "flex-end" }}>
                <button type="submit" className="btn btn-secondary" disabled={addingTarget || !targetValue.trim()}>
                  <TargetIcon width={13} height={13} />
                  {addingTarget ? "Adding…" : "Add target"}
                </button>
              </div>
            </form>
          </div>

          {/* ── Targets List Table ─────────────────────────────────────── */}
          <div className="card" style={{ padding: 0, overflow: "hidden" }}>
            <div className="card-header" style={{ padding: "18px 20px" }}>
              <h2 style={{ margin: 0, fontSize: 15 }}>Configured Targets ({targets.length})</h2>
            </div>

            {loading ? (
              <div style={{ padding: 32 }}>
                {[1, 2, 3].map((i) => (
                  <div key={i} className="skeleton" style={{ height: 40, borderRadius: 6, marginBottom: 8 }} />
                ))}
              </div>
            ) : targets.length === 0 ? (
              <EmptyState
                icon={<TargetIcon />}
                title="No targets configured yet"
                description="Add a URL, domain, IP, CIDR range, or local codebase path above to start scanning."
              />
            ) : (
              <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>Value</th>
                      <th>Status</th>
                      <th>Added</th>
                      <th style={{ textAlign: "right" }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {targets.map((target) => (
                      <tr key={target.id}>
                        <td>
                          <span className="badge kind" style={{ display: "inline-flex", gap: 5, alignItems: "center" }}>
                            {TARGET_KIND_ICONS[target.kind]}
                            {target.kind}
                          </span>
                        </td>
                        <td>
                          <code style={{ fontSize: 13 }}>{target.value}</code>
                        </td>
                        <td>
                          <span className={`active-pill ${target.is_active ? "yes" : "no"}`}>
                            {target.is_active ? "● Active" : "● Inactive"}
                          </span>
                        </td>
                        <td>
                          <span className="muted" style={{ fontSize: 12 }}>
                            {relativeTime(target.created_at)}
                          </span>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            title="Delete target"
                            onClick={() => setTargetToDelete(target)}
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
            )}
          </div>
        </div>
      )}

      {/* ── Confirm Modals ──────────────────────────────────────────── */}
      <ConfirmModal
        isOpen={showDeleteProjectModal}
        title="Delete Project?"
        message={`Are you sure you want to permanently delete project "${project?.name}"? All its targets, scan history, and findings will be deleted.`}
        confirmLabel="Delete Project"
        cancelLabel="Cancel"
        isDestructive
        isBusy={isDeletingProject}
        onConfirm={executeDeleteProject}
        onCancel={() => setShowDeleteProjectModal(false)}
      />

      <ConfirmModal
        isOpen={targetToDelete !== null}
        title="Delete Target?"
        message={`Are you sure you want to remove target "${targetToDelete?.value}" from this project?`}
        confirmLabel="Delete Target"
        cancelLabel="Cancel"
        isDestructive
        isBusy={isDeletingTarget}
        onConfirm={executeDeleteTarget}
        onCancel={() => setTargetToDelete(null)}
      />

      <ConfirmModal
        isOpen={scanToDelete !== null}
        title="Delete Scan Run?"
        message={`Are you sure you want to delete this ${scanToDelete?.tool} scan run and its discovered findings?`}
        confirmLabel="Delete Scan"
        cancelLabel="Cancel"
        isDestructive
        isBusy={isDeletingScan}
        onConfirm={executeDeleteScan}
        onCancel={() => setScanToDelete(null)}
      />
    </div>
  );
}
