from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from secplat.domain.scanning.project import Project
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.value_objects import (
    ProjectId,
    ScanId,
    ScanStatus,
    TargetKind,
    TargetRef,
    ToolName,
)
from secplat.infrastructure.persistence.repositories import (
    SqlAlchemyProjectRepository,
    SqlAlchemyScanRepository,
)
from tests.conftest import FakeTaskQueue, SessionFactory


def _persist_scan(
    session: Session,
    project_id: uuid.UUID,
    tool: ToolName,
    stats: dict[str, Any],
) -> None:
    scan_id = uuid.uuid4()
    scan = Scan(
        id=ScanId(scan_id),
        project_id=ProjectId(project_id),
        target=TargetRef(TargetKind.PATH, "/srv/project"),
        tool=tool,
        status=ScanStatus.COMPLETED,
        started_at=None,
        finished_at=datetime.now(UTC),
    )
    scan_repo = SqlAlchemyScanRepository(session)
    scan_repo.save(scan)
    scan_repo.update_stats(ScanId(scan_id), stats)


def test_codebase_pipeline_endpoint_queues_task(
    client: TestClient, fake_queue: FakeTaskQueue
) -> None:
    project = client.post("/api/v1/projects", json={"name": "Pipeline Project"}).json()
    project_id = project["id"]

    response = client.post(
        f"/api/v1/projects/{project_id}/pipelines/codebase",
        json={
            "target": {"kind": "path", "value": "repo"},
            "tools": ["gitleaks", "semgrep", "trivy", "checkov"],
        },
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "queued"
    assert "Full Codebase Audit queued" in data["message"]
    assert any(t.startswith("codebase:") for t in fake_queue.enqueued)


def test_project_security_score_endpoint(
    client: TestClient, sessions: SessionFactory
) -> None:
    project_id = uuid.uuid4()
    session = sessions()
    try:
        project_repo = SqlAlchemyProjectRepository(session)
        project_repo.save(Project(id=ProjectId(project_id), name="Scored Project"))
        _persist_scan(
            session,
            project_id,
            ToolName.GITLEAKS,
            {"findings": 1, "by_severity": {"critical": 1}},
        )
        _persist_scan(
            session,
            project_id,
            ToolName.SEMGREP,
            {"findings": 1, "by_severity": {"high": 1}},
        )
    finally:
        session.close()

    response = client.get(f"/api/v1/projects/{project_id}/security-score")
    assert response.status_code == 200
    score_data = response.json()
    # 100 - (25 + 10) = 65 -> Grade C
    assert score_data["score"] == 65
    assert score_data["grade"] == "C"
    assert score_data["total_findings"] == 2
    assert score_data["penalties"] == 35
    assert score_data["categories"]["secrets"]["score"] == 75
    assert score_data["categories"]["sast"]["score"] == 90
