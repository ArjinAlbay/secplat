from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from secplat.domain.scanning.project import Project, Target
from secplat.domain.scanning.records import FindingRecord, FindingView, ScanResultView
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.value_objects import (
    ProjectId,
    ScanId,
    ScanStatus,
    Severity,
    TargetId,
    TargetRef,
    ToolName,
)


class ProjectRepository(ABC):
    @abstractmethod
    def save(self, project: Project) -> None: ...

    @abstractmethod
    def get(self, project_id: ProjectId) -> Project | None: ...

    @abstractmethod
    def list(self) -> list[Project]: ...

    @abstractmethod
    def delete(self, project_id: ProjectId) -> None: ...

    @abstractmethod
    def add_target(self, target: Target) -> Target: ...

    @abstractmethod
    def get_target(self, project_id: ProjectId, target_id: TargetId) -> Target | None: ...

    @abstractmethod
    def list_targets(self, project_id: ProjectId) -> list[Target]: ...

    @abstractmethod
    def delete_target(self, project_id: ProjectId, target_id: TargetId) -> None: ...


class ScanRepository(ABC):
    @abstractmethod
    def save(self, scan: Scan) -> None: ...

    @abstractmethod
    def get(self, scan_id: ScanId) -> Scan | None: ...

    @abstractmethod
    def list_by_project(self, project_id: ProjectId) -> list[Scan]: ...

    @abstractmethod
    def delete(self, scan_id: ScanId) -> None: ...

    @abstractmethod
    def delete_by_project(self, project_id: ProjectId) -> None: ...

    @abstractmethod
    def list_recent(self, limit: int) -> list[Scan]: ...

    @abstractmethod
    def update_stats(self, scan_id: ScanId, stats: Mapping[str, Any]) -> None: ...

    @abstractmethod
    def add_results(
        self, scan_id: ScanId, tool: ToolName, raw_lines: Sequence[Mapping[str, Any]]
    ) -> None: ...

    @abstractmethod
    def upsert_findings(
        self, scan_id: ScanId, project_id: ProjectId, findings: Sequence[FindingRecord]
    ) -> None: ...

    @abstractmethod
    def list_results(self, scan_id: ScanId, limit: int, offset: int) -> list[ScanResultView]: ...

    @abstractmethod
    def list_findings(
        self, scan_id: ScanId, severity: Severity | None, limit: int, offset: int
    ) -> list[FindingView]: ...

    @abstractmethod
    def list_by_status(self, status: ScanStatus, updated_before: datetime) -> list[Scan]: ...


class TaskQueue(ABC):
    @abstractmethod
    def enqueue_scan(self, scan_id: ScanId, task_id: str) -> None: ...

    @abstractmethod
    def enqueue_recon_pipeline(
        self,
        project_id: ProjectId,
        target_ref: TargetRef,
        pipeline_id: str,
        nuclei_severity: list[str] | None = None,
    ) -> None: ...

    @abstractmethod
    def enqueue_codebase_pipeline(
        self,
        project_id: ProjectId,
        target_ref: TargetRef,
        pipeline_id: str,
        tools: list[str] | None = None,
    ) -> None: ...

    @abstractmethod
    def revoke(self, task_id: str) -> None: ...


@dataclass(frozen=True, slots=True)
class RunOutcome:
    returncode: int
    stderr_tail: str
    timed_out: bool

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class ToolRunner(ABC):
    @abstractmethod
    def run(
        self, argv: Sequence[str], timeout_s: int, on_line: Callable[[str], None]
    ) -> RunOutcome: ...


class ToolAdapter(Protocol):
    tool: ToolName

    def build_args(self, target: TargetRef, config: Mapping[str, Any]) -> list[str]: ...

    def parse_line(self, line: Mapping[str, Any]) -> FindingRecord | None: ...

    def parse_report(self, report: Mapping[str, Any]) -> Sequence[FindingRecord]: ...


class ToolAdapterFactory(Protocol):
    def __call__(self, tool: ToolName) -> ToolAdapter: ...
