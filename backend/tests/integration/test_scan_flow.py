from __future__ import annotations

import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from secplat.application.scanning.commands import ExecuteScan
from secplat.domain.scanning.value_objects import ScanId
from secplat.infrastructure.persistence.repositories import SqlAlchemyScanRepository
from secplat.infrastructure.tools.nuclei.adapter import NucleiAdapter
from secplat.infrastructure.tools.subprocess_runner import SubprocessToolRunner
from tests.conftest import FakeTaskQueue, SessionFactory

STUB_SCRIPT = """#!/usr/bin/env python3
import json

rows = [
    {
        "template-id": "stub-template",
        "info": {"name": "Stub Finding", "severity": "high"},
        "host": "https://example.com",
        "matched-at": "https://example.com/a",
        "extracted-results": ["tls11"],
        "matcher-status": True,
    },
    {
        "template-id": "stub-template",
        "info": {"name": "Stub Finding", "severity": "high"},
        "host": "https://example.com",
        "matched-at": "https://example.com/a",
        "extracted-results": ["tls10"],
    },
    {
        "template-id": "stub-template-2",
        "info": {"name": "Stub Low", "severity": "low"},
        "host": "https://example.com",
        "matched-at": "https://example.com/b",
    },
    {"not-a-finding": True},
]
for row in rows:
    print(json.dumps(row))
"""


def _make_stub(tmp_path: Path) -> Path:
    stub = tmp_path / "nuclei-stub"
    stub.write_text(STUB_SCRIPT)
    stub.chmod(0o755)
    return stub


def _run_worker_side(
    sessions: SessionFactory, scan_id: str, stub: Path, template_dir: Path
) -> None:
    session: Session = sessions()
    try:
        handler = ExecuteScan(
            scans=SqlAlchemyScanRepository(session),
            adapters=lambda tool: NucleiAdapter(
                binary=str(stub), template_dir=str(template_dir)
            ),
            runner=SubprocessToolRunner(),
            timeout_s=30,
        )
        handler(ScanId(uuid.UUID(scan_id)))
    finally:
        session.close()


def test_full_scan_lifecycle(
    client: TestClient,
    sessions: SessionFactory,
    fake_queue: FakeTaskQueue,
    tmp_path: Path,
) -> None:
    stub = _make_stub(tmp_path)
    project = client.post("/api/v1/projects", json={"name": "Demo"}).json()
    assert project["name"] == "Demo"

    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={
            "tool": "nuclei",
            "target": {"kind": "url", "value": "https://example.com"},
            "config": {"severity": ["high", "low"], "rate_limit": 50},
        },
    )
    assert response.status_code == 202
    scan = response.json()
    assert scan["status"] == "queued"
    assert uuid.UUID(scan["task_id"])
    assert fake_queue.enqueued == [scan["id"]]
    assert fake_queue.task_ids == [scan["task_id"]]

    _run_worker_side(sessions, scan["id"], stub, tmp_path)

    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["status"] == "completed"
    assert detail["stats"]["findings"] == 2
    assert detail["stats"]["by_severity"] == {"high": 1, "low": 1}
    assert detail["error"] is None

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert len(findings) == 2
    assert {finding["severity"] for finding in findings} == {"high", "low"}

    high = client.get(
        f"/api/v1/scans/{scan['id']}/findings", params={"severity": "high"}
    ).json()
    assert len(high) == 1
    assert high[0]["template_id"] == "stub-template"

    results = client.get(f"/api/v1/scans/{scan['id']}/results").json()
    assert len(results) == 4

    scans_list = client.get(f"/api/v1/projects/{project['id']}/scans").json()
    assert len(scans_list) == 1
    assert scans_list[0]["status"] == "completed"

    recent = client.get("/api/v1/scans", params={"limit": 5}).json()
    assert any(item["id"] == scan["id"] for item in recent)
    assert all(item["target"]["value"] for item in recent)


def test_existing_target_can_be_rescanned(
    client: TestClient, sessions: SessionFactory, tmp_path: Path
) -> None:
    stub = _make_stub(tmp_path)
    project = client.post("/api/v1/projects", json={"name": "P2"}).json()
    target = client.post(
        f"/api/v1/projects/{project['id']}/targets",
        json={"kind": "url", "value": "https://example.com"},
    ).json()

    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={"tool": "nuclei", "target_id": target["id"]},
    )
    assert response.status_code == 202
    scan = response.json()
    assert scan["target"]["value"] == "https://example.com"

    _run_worker_side(sessions, scan["id"], stub, tmp_path)
    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["status"] == "completed"


def test_cancel_queued_scan(client: TestClient, fake_queue: FakeTaskQueue) -> None:
    project = client.post("/api/v1/projects", json={"name": "P3"}).json()
    scan = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={"tool": "nuclei", "target": {"kind": "url", "value": "https://example.com"}},
    ).json()

    response = client.post(f"/api/v1/scans/{scan['id']}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert fake_queue.revoked == [scan["task_id"]]


def test_invalid_config_key_rejected(client: TestClient) -> None:
    project = client.post("/api/v1/projects", json={"name": "P4"}).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={
            "tool": "nuclei",
            "target": {"kind": "url", "value": "https://example.com"},
            "config": {"evil_flag": True},
        },
    )
    assert response.status_code == 422


def test_unknown_scan_returns_404(client: TestClient) -> None:
    assert client.get(f"/api/v1/scans/{uuid.uuid4()}").status_code == 404


def test_delete_scan_and_project_flow(client: TestClient, fake_queue: FakeTaskQueue) -> None:
    project = client.post("/api/v1/projects", json={"name": "P-Delete"}).json()
    scan = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={"tool": "nuclei", "target": {"kind": "url", "value": "https://example.com"}},
    ).json()

    res = client.delete(f"/api/v1/scans/{scan['id']}")
    assert res.status_code == 204
    assert client.get(f"/api/v1/scans/{scan['id']}").status_code == 404

    target = client.post(
        f"/api/v1/projects/{project['id']}/targets",
        json={"kind": "domain", "value": "example.org"},
    ).json()
    del_target_url = f"/api/v1/projects/{project['id']}/targets/{target['id']}"
    assert client.delete(del_target_url).status_code == 204

    assert client.delete(f"/api/v1/projects/{project['id']}").status_code == 204
    assert client.get(f"/api/v1/projects/{project['id']}").status_code == 404
