from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ProjectOverviewRow:
    project_name: str
    total_findings: int
    counts_by_severity: dict[str, int]
    security_score: int = 100
    grade: str = "A"



@dataclass(frozen=True, slots=True)
class OverviewReportModel:
    title: str
    generated_at: datetime
    projects_reported: int
    rows: tuple[ProjectOverviewRow, ...]
