from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from secplat.application.reports.builders import BuildProjectOverview
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.value_objects import (
    ProjectId,
    ScanId,
    ScanStatus,
    TargetKind,
    TargetRef,
    ToolName,
)

PROJECT_ID: Any = uuid.uuid4()
BASE_TIME = datetime.now(UTC)


def _scan(
    tool: ToolName,
    value: str,
    status: ScanStatus = ScanStatus.COMPLETED,
    created_offset_s: float = 0,
    stats: dict[str, Any] | None = None,
) -> Scan:
    scan = Scan(
        id=ScanId(uuid.uuid4()),
        project_id=ProjectId(PROJECT_ID),
        target=TargetRef(TargetKind.PATH, value),
        tool=tool,
        status=status,
    )
    scan.created_at = BASE_TIME + timedelta(seconds=created_offset_s)
    scan.stats = stats
    return scan


def test_overview_sums_latest_completed_scan_per_tool_and_target() -> None:
    scans = [
        _scan(ToolName.SEMGREP, "/srv/demo", stats={"findings": 3, "by_severity": {"high": 3}}),
        _scan(
            ToolName.SEMGREP,
            "/srv/demo",
            created_offset_s=10,
            stats={"findings": 5, "by_severity": {"critical": 1, "high": 4}},
        ),
        _scan(ToolName.TRIVY, "/srv/demo", stats={"findings": 2, "by_severity": {"medium": 2}}),
        _scan(ToolName.TRIVY, "/srv/other", stats={"findings": 4, "by_severity": {"low": 4}}),
        _scan(ToolName.TRIVY, "/srv/demo", status=ScanStatus.RUNNING),
    ]
    model = BuildProjectOverview()([("Demo", scans)])
    assert model.projects_reported == 1
    row = model.rows[0]
    assert row.project_name == "Demo"
    assert row.total_findings == 11
    assert row.counts_by_severity == {"critical": 1, "high": 4, "medium": 2, "low": 4}
    # 100 - (1*25 + 4*10 + 2*3 + 4*1) = 100 - (25 + 40 + 6 + 4) = 100 - 75 = 25 -> Grade F
    assert row.security_score == 25
    assert row.grade == "F"


def test_overview_keeps_latest_scan_only_for_same_tool_and_target() -> None:
    scans = [
        _scan(ToolName.SEMGREP, "/srv/demo", stats={"findings": 3, "by_severity": {"high": 3}}),
        _scan(
            ToolName.SEMGREP,
            "/srv/demo",
            created_offset_s=10,
            stats={"findings": 5, "by_severity": {"high": 5}},
        ),
    ]
    model = BuildProjectOverview()([("Demo", scans)])
    assert model.rows[0].total_findings == 5
    assert model.rows[0].counts_by_severity == {"high": 5}
    assert model.rows[0].security_score == 50  # 100 - (5*10) = 50
    assert model.rows[0].grade == "D"


def test_overview_skips_projects_without_completed_scans() -> None:
    running = _scan(ToolName.SEMGREP, "/srv/demo", status=ScanStatus.RUNNING)
    model = BuildProjectOverview()([("Empty", []), ("Busy", [running])])
    assert model.projects_reported == 0
    assert model.rows == ()


def test_build_project_security_score() -> None:
    from secplat.application.reports.builders import BuildProjectSecurityScore

    scans = [
        _scan(
            ToolName.GITLEAKS,
            "/srv/repo",
            stats={"findings": 1, "by_severity": {"critical": 1}},
        ),
        _scan(
            ToolName.SEMGREP,
            "/srv/repo",
            stats={"findings": 2, "by_severity": {"medium": 2}},
        ),
        _scan(ToolName.TRIVY, "/srv/repo", stats={"findings": 0, "by_severity": {}}),
        _scan(ToolName.CHECKOV, "/srv/repo", stats={"findings": 1, "by_severity": {"low": 1}}),
    ]
    score = BuildProjectSecurityScore()(scans)
    # Total penalties: 25 + 6 + 0 + 1 = 32 -> score = 68 -> Grade C
    assert score.score == 68
    assert score.grade == "C"
    assert score.total_findings == 4
    assert score.categories["secrets"].score == 75
    assert score.categories["sast"].score == 94
    assert score.categories["sca"].score == 100
    assert score.categories["iac"].score == 99

