from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from secplat.domain.scanning.value_objects import ProjectId, TargetId, TargetRef


@dataclass
class Project:
    id: ProjectId
    name: str
    description: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class Target:
    id: TargetId
    project_id: ProjectId
    ref: TargetRef
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
