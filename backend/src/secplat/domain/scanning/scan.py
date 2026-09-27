from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from secplat.domain.scanning.errors import InvalidTransition
from secplat.domain.scanning.value_objects import (
    ProjectId,
    ScanId,
    ScanStatus,
    TargetId,
    TargetRef,
    ToolName,
)


@dataclass
class Scan:
    id: ScanId
    project_id: ProjectId
    target: TargetRef
    tool: ToolName
    config: Mapping[str, Any] = field(default_factory=dict)
    target_id: TargetId | None = None
    status: ScanStatus = ScanStatus.PENDING
    task_id: str | None = None
    stats: dict[str, Any] | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def mark_queued(self, task_id: str) -> None:
        self._guard(ScanStatus.PENDING, ScanStatus.QUEUED)
        self.task_id = task_id
        self.status = ScanStatus.QUEUED

    def mark_running(self) -> None:
        self._guard(ScanStatus.QUEUED, ScanStatus.RUNNING)
        self.started_at = datetime.now(UTC)
        self.status = ScanStatus.RUNNING

    def complete(self, stats: Mapping[str, Any]) -> None:
        self._guard(ScanStatus.RUNNING, ScanStatus.COMPLETED)
        self.stats = dict(stats)
        self.finished_at = datetime.now(UTC)
        self.status = ScanStatus.COMPLETED

    def fail(self, error: str) -> None:
        if self.status.is_terminal:
            raise InvalidTransition(self.status.value, "failed")
        self.error = error
        self.finished_at = datetime.now(UTC)
        self.status = ScanStatus.FAILED

    def cancel(self) -> None:
        if self.status.is_terminal:
            raise InvalidTransition(self.status.value, "cancelled")
        self.finished_at = datetime.now(UTC)
        self.status = ScanStatus.CANCELLED

    def _guard(self, expected: ScanStatus, attempted: ScanStatus) -> None:
        if self.status is not expected:
            raise InvalidTransition(self.status.value, attempted.value)
