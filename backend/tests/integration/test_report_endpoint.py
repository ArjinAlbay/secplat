from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
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
from tests.conftest import SessionFactory

PROJECT_ID = uuid.uuid4()
OTHER_PROJECT_ID = uuid.uuid4()
SCAN_ID = uuid.uuid4()


def _persist_scan(
    session: Session,
    scan_id: uuid.UUID,
    project_id: uuid.UUID,
    stats: dict[str, Any],
) -> None:
    scan = Scan(
        id=ScanId(scan_id),
        project_id=ProjectId(project_id),
        target=TargetRef(TargetKind.URL, "https://example.com"),
        tool=ToolName.SEMGREP,
        status=ScanStatus.COMPLETED,
        started_at=None,
        finished_at=datetime.now(UTC),
    )
    scan_repo = SqlAlchemyScanRepository(session)
    scan_repo.save(scan)
    scan_repo.update_stats(ScanId(scan_id), stats)


@pytest.fixture()
def completed_semgrep_scan(sessions: SessionFactory) -> None:
    session: Session = sessions()
    try:
        project_repo = SqlAlchemyProjectRepository(session)
        project_repo.save(Project(id=ProjectId(PROJECT_ID), name="Demo"))
        project_repo.save(Project(id=ProjectId(OTHER_PROJECT_ID), name="Other"))
        _persist_scan(
            session,
            SCAN_ID,
            PROJECT_ID,
            {"findings": 2, "by_severity": {"high": 1, "medium": 1}},
        )
        _persist_scan(
            session,
            uuid.uuid4(),
            OTHER_PROJECT_ID,
            {"findings": 5, "by_severity": {"critical": 2, "medium": 3}},
        )
    finally:
        session.close()


def test_overview_json_endpoint(
    client: TestClient, sessions: SessionFactory, completed_semgrep_scan: None
) -> None:
    response = client.get("/api/v1/reports/overview", params={"format": "json"})
    assert response.status_code == 200
    body = response.json()
    assert body["projects_reported"] == 2
    rows = {row["project_name"]: row for row in body["rows"]}
    assert rows["Demo"]["total_findings"] == 2
    assert rows["Demo"]["counts_by_severity"] == {"high": 1, "medium": 1}
    assert rows["Other"]["total_findings"] == 5
    assert rows["Other"]["counts_by_severity"] == {"critical": 2, "medium": 3}


def test_overview_html_endpoint(
    client: TestClient, sessions: SessionFactory, completed_semgrep_scan: None
) -> None:
    html = client.get("/api/v1/reports/overview", params={"format": "html"})
    assert html.status_code == 200
    assert html.headers["content-type"].startswith("text/html")
    assert "Demo" in html.text
    assert "Other" in html.text


def test_overview_pdf_endpoint(
    client: TestClient, sessions: SessionFactory, completed_semgrep_scan: None
) -> None:
    response = client.get("/api/v1/reports/overview", params={"format": "pdf"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content[:5] == b"%PDF-"
    assert "secplat-overview" in response.headers.get("content-disposition", "")


def test_overview_default_format_is_pdf(
    client: TestClient, sessions: SessionFactory, completed_semgrep_scan: None
) -> None:
    response = client.get("/api/v1/reports/overview")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"


def test_overview_invalid_format_rejected(client: TestClient) -> None:
    assert (
        client.get("/api/v1/reports/overview", params={"format": "docx"}).status_code == 422
    )
