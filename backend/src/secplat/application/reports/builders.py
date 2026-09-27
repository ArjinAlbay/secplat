from __future__ import annotations

from datetime import datetime

from secplat.application.reports.model import OverviewReportModel, ProjectOverviewRow
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.scoring import (
    TOOL_CATEGORY_MAP,
    SecurityScore,
    calculate_security_score,
)
from secplat.domain.scanning.value_objects import ScanStatus


class BuildProjectSecurityScore:
    def __call__(self, scans: list[Scan]) -> SecurityScore:
        latest: dict[tuple[str, str], Scan] = {}
        for scan in scans:
            if scan.status is not ScanStatus.COMPLETED:
                continue
            key = (scan.tool.value, scan.target.value)
            current = latest.get(key)
            if current is None or scan.created_at > current.created_at:
                latest[key] = scan

        total_counts: dict[str, int] = {}
        category_counts: dict[str, dict[str, int]] = {}

        for scan in latest.values():
            tool_name = scan.tool.value
            category = TOOL_CATEGORY_MAP.get(tool_name, "other")
            if category not in category_counts:
                category_counts[category] = {}

            stats = scan.stats or {}
            for severity, count in (stats.get("by_severity") or {}).items():
                cnt = int(count)
                total_counts[severity] = total_counts.get(severity, 0) + cnt
                category_counts[category][severity] = (
                    category_counts[category].get(severity, 0) + cnt
                )

        return calculate_security_score(total_counts, category_counts)


class BuildProjectOverview:
    def __call__(self, scans_by_project: list[tuple[str, list[Scan]]]) -> OverviewReportModel:
        score_builder = BuildProjectSecurityScore()
        rows: list[ProjectOverviewRow] = []
        for project_name, scans in scans_by_project:
            has_completed = any(s.status is ScanStatus.COMPLETED for s in scans)
            if not has_completed:
                continue
            score = score_builder(scans)
            rows.append(
                ProjectOverviewRow(
                    project_name=project_name,
                    total_findings=score.total_findings,
                    counts_by_severity=score.counts_by_severity,
                    security_score=score.score,
                    grade=score.grade,
                )
            )
        return OverviewReportModel(
            title="Şirket Güvenlik Özeti",
            generated_at=datetime.now(),
            projects_reported=len(rows),
            rows=tuple(rows),
        )

