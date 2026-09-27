from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secplat.application.projects.dto import TargetIn
from secplat.domain.scanning.project import Project, Target
from secplat.domain.scanning.records import FindingView, ScanResultView
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.scoring import CategoryScore, SecurityScore
from secplat.domain.scanning.value_objects import ScanStatus, Severity, TargetKind, ToolName

SeverityName = Literal["critical", "high", "medium", "low", "info", "unknown"]


class NucleiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: list[SeverityName] | None = None
    tags: list[Annotated[str, Field(pattern=r"^[a-z0-9_-]+$")]] | None = None
    exclude_tags: list[Annotated[str, Field(pattern=r"^[a-z0-9_-]+$")]] | None = None
    template_ids: list[Annotated[str, Field(pattern=r"^[a-zA-Z0-9._-]+$")]] | None = None
    exclude_template_ids: list[Annotated[str, Field(pattern=r"^[a-zA-Z0-9._-]+$")]] | None = None
    custom_headers: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+:\s*.+$")]] | None = None
    stop_at_first_match: bool = False
    rate_limit: int = Field(150, ge=1, le=600)
    concurrency: int = Field(25, ge=1, le=100)
    timeout: int = Field(10, ge=1, le=120)
    omit_raw: bool = False
    no_interactsh: bool = True
    restrict_local_network: bool = False


class SubfinderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[Annotated[str, Field(pattern=r"^[a-z0-9_-]+$")]] | None = None
    exclude_sources: list[Annotated[str, Field(pattern=r"^[a-z0-9_-]+$")]] | None = None
    all_sources: bool = False
    recursive: bool = False
    rate_limit: int = Field(100, ge=1, le=600)
    timeout: int = Field(30, ge=1, le=120)
    max_time: int = Field(10, ge=1, le=120)
    exclude_ip: bool = False


class SemgrepConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    config: str = Field("auto", min_length=1, max_length=512)


class TrivyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanners: list[str] = Field(default_factory=lambda: ["vuln", "secret", "misconfig"])
    skip_dirs: list[str] = Field(default_factory=list)
    skip_db_update: bool = False
    offline_scan: bool = False


class GitleaksConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    no_git: bool = False
    redact: bool = False


class CheckovConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: str | None = None
    skip_path: list[str] = Field(default_factory=list)


class HttpxConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tech_detect: bool = True
    follow_redirects: bool = False
    ports: list[int | str] | None = None
    path: str | None = None
    threads: int = Field(50, ge=1, le=300)
    rate_limit: int = Field(150, ge=1, le=1000)
    timeout: int = Field(10, ge=1, le=120)


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: Literal["nuclei", "subfinder", "semgrep", "trivy", "gitleaks", "checkov", "httpx"]
    target_id: uuid.UUID | None = None
    target: TargetIn | None = None
    config: (
        NucleiConfig
        | SubfinderConfig
        | SemgrepConfig
        | TrivyConfig
        | GitleaksConfig
        | CheckovConfig
        | HttpxConfig
    ) = Field(default_factory=NucleiConfig)

    @model_validator(mode="before")
    @classmethod
    def _config_for_tool(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        config_cls = {
            "nuclei": NucleiConfig,
            "subfinder": SubfinderConfig,
            "semgrep": SemgrepConfig,
            "trivy": TrivyConfig,
            "gitleaks": GitleaksConfig,
            "checkov": CheckovConfig,
            "httpx": HttpxConfig,
        }.get(data.get("tool"))
        if config_cls is None:
            return data
        raw = data.get("config")
        if isinstance(raw, config_cls):
            return data
        if raw is None:
            raw = {}
        if isinstance(raw, dict):
            return {**data, "config": config_cls(**raw)}
        return data


class BatchScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scans: list[ScanCreate] = Field(min_length=1, max_length=20)


class TargetRefOut(BaseModel):
    kind: TargetKind
    value: str


class ReconPipelineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: uuid.UUID | None = None
    target: TargetIn | None = None
    nuclei_severity: list[SeverityName] | None = None


class ReconPipelineResponse(BaseModel):
    pipeline_id: str
    project_id: uuid.UUID
    target: TargetRefOut
    status: str = "queued"
    message: str


class CodebasePipelineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: uuid.UUID | None = None
    target: TargetIn | None = None
    tools: list[str] | None = None


class CodebasePipelineResponse(BaseModel):
    pipeline_id: str
    project_id: uuid.UUID
    target: TargetRefOut
    status: str = "queued"
    message: str


class CategoryScoreOut(BaseModel):
    category: str
    score: int
    grade: str
    total_findings: int
    counts_by_severity: dict[str, int]

    @classmethod
    def from_domain(cls, score: CategoryScore) -> CategoryScoreOut:
        return cls(
            category=score.category,
            score=score.score,
            grade=score.grade,
            total_findings=score.total_findings,
            counts_by_severity=dict(score.counts_by_severity),
        )


class SecurityScoreOut(BaseModel):
    score: int
    grade: str
    total_findings: int
    penalties: int
    counts_by_severity: dict[str, int]
    categories: dict[str, CategoryScoreOut]

    @classmethod
    def from_domain(cls, score: SecurityScore) -> SecurityScoreOut:
        return cls(
            score=score.score,
            grade=score.grade,
            total_findings=score.total_findings,
            penalties=score.penalties,
            counts_by_severity=dict(score.counts_by_severity),
            categories={k: CategoryScoreOut.from_domain(v) for k, v in score.categories.items()},
        )


class ProjectOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime

    @classmethod
    def from_domain(cls, project: Project) -> ProjectOut:
        return cls(
            id=project.id,
            name=project.name,
            description=project.description,
            created_at=project.created_at,
        )


class TargetOut(BaseModel):
    id: uuid.UUID
    kind: TargetKind
    value: str
    is_active: bool
    created_at: datetime

    @classmethod
    def from_domain(cls, target: Target) -> TargetOut:
        return cls(
            id=target.id,
            kind=target.ref.kind,
            value=target.ref.value,
            is_active=target.is_active,
            created_at=target.created_at,
        )


class ScanOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID | None
    tool: ToolName
    status: ScanStatus
    target: TargetRefOut
    config: dict[str, Any]
    task_id: str | None
    stats: dict[str, Any] | None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime

    @classmethod
    def from_domain(cls, scan: Scan) -> ScanOut:
        return cls(
            id=scan.id,
            project_id=scan.project_id,
            target_id=scan.target_id,
            tool=scan.tool,
            status=scan.status,
            target=TargetRefOut(kind=scan.target.kind, value=scan.target.value),
            config=dict(scan.config),
            task_id=scan.task_id,
            stats=scan.stats,
            error=scan.error,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            created_at=scan.created_at,
        )


class FindingOut(BaseModel):
    severity: Severity
    template_id: str
    name: str
    matched_at: str
    host: str
    extracted: list[str]
    status: str
    first_seen_at: datetime | None
    last_seen_at: datetime | None

    @classmethod
    def from_view(cls, view: FindingView) -> FindingOut:
        return cls(
            severity=view.severity,
            template_id=view.template_id,
            name=view.name,
            matched_at=view.matched_at,
            host=view.host,
            extracted=list(view.extracted),
            status=view.status,
            first_seen_at=view.first_seen_at,
            last_seen_at=view.last_seen_at,
        )


class ScanResultOut(BaseModel):
    tool: str
    raw: dict[str, Any]
    created_at: datetime

    @classmethod
    def from_view(cls, view: ScanResultView) -> ScanResultOut:
        return cls(tool=view.tool, raw=dict(view.raw), created_at=view.created_at)


class ScanDiffSummary(BaseModel):
    new_count: int
    fixed_count: int
    unchanged_count: int
    current_total: int
    previous_total: int


class ScanDiffOut(BaseModel):
    base_scan_id: uuid.UUID
    target_scan_id: uuid.UUID | None
    summary: ScanDiffSummary
    new_findings: list[FindingOut]
    fixed_findings: list[FindingOut]
    unchanged_findings: list[FindingOut]

