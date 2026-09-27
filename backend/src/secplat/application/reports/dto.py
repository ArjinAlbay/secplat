from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from secplat.application.reports.model import OverviewReportModel, ProjectOverviewRow


class OverviewRowOut(BaseModel):
    project_name: str
    total_findings: int
    counts_by_severity: dict[str, int]
    security_score: int = 100
    grade: str = "A"

    @classmethod
    def from_model(cls, row: ProjectOverviewRow) -> OverviewRowOut:
        return cls(
            project_name=row.project_name,
            total_findings=row.total_findings,
            counts_by_severity=dict(row.counts_by_severity),
            security_score=row.security_score,
            grade=row.grade,
        )


class OverviewOut(BaseModel):
    title: str
    generated_at: datetime
    projects_reported: int
    rows: list[OverviewRowOut]

    @classmethod
    def from_model(cls, model: OverviewReportModel) -> OverviewOut:
        return cls(
            title=model.title,
            generated_at=model.generated_at,
            projects_reported=model.projects_reported,
            rows=[OverviewRowOut.from_model(row) for row in model.rows],
        )
