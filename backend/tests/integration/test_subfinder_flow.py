from __future__ import annotations

import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from secplat.application.scanning.commands import ExecuteScan
from secplat.domain.scanning.value_objects import ScanId
from secplat.infrastructure.persistence.repositories import SqlAlchemyScanRepository
from secplat.infrastructure.tools.httpx.adapter import HttpxAdapter
from secplat.infrastructure.tools.subfinder.adapter import SubfinderAdapter
from secplat.infrastructure.tools.subprocess_runner import SubprocessToolRunner
from tests.conftest import SessionFactory

HTTPX_STUB = """#!/usr/bin/env python3
import json

rows = [
    {
        "url": "https://example.com",
        "input": "example.com",
        "host": "example.com",
        "port": "443",
        "scheme": "https",
        "status_code": 200,
        "title": "Example Domain",
        "webserver": "nginx",
        "tech": ["Nginx"],
    },
    {
        "url": "http://api.example.com",
        "input": "api.example.com",
        "host": "api.example.com",
        "port": "80",
        "scheme": "http",
        "status_code": 403,
        "title": "Forbidden",
        "webserver": "cloudflare",
    },
    {"failed": True, "url": "http://dead.example.com"},
]
for row in rows:
    print(json.dumps(row))
"""

SUBFINDER_STUB = """#!/usr/bin/env python3
import json

rows = [
    {"host": "a.example.com", "input": "example.com", "sources": ["anubis", "crtsh"]},
    {"host": "a.example.com", "input": "example.com", "sources": ["crtsh"]},
    {"host": "b.example.com", "input": "example.com", "sources": ["anubis"]},
    {"not-a-finding": True},
]
for row in rows:
    print(json.dumps(row))
"""


def _make_stub(tmp_path: Path) -> Path:
    stub = tmp_path / "subfinder-stub"
    stub.write_text(SUBFINDER_STUB)
    stub.chmod(0o755)
    return stub


def _run_worker_side(sessions: SessionFactory, scan_id: str, stub: Path) -> None:
    session: Session = sessions()
    try:
        handler = ExecuteScan(
            scans=SqlAlchemyScanRepository(session),
            adapters=lambda tool: SubfinderAdapter(binary=str(stub)),
            runner=SubprocessToolRunner(),
            timeout_s=30,
        )
        handler(ScanId(uuid.UUID(scan_id)))
    finally:
        session.close()


def test_subfinder_scan_lifecycle(
    client: TestClient, sessions: SessionFactory, tmp_path: Path
) -> None:
    stub = _make_stub(tmp_path)
    project = client.post("/api/v1/projects", json={"name": "Subfinder Demo"}).json()

    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={
            "tool": "subfinder",
            "target": {"kind": "domain", "value": "example.com"},
            "config": {"sources": ["crtsh", "anubis"], "rate_limit": 50},
        },
    )
    assert response.status_code == 202
    scan = response.json()
    assert scan["status"] == "queued"
    assert scan["tool"] == "subfinder"
    assert scan["config"]["sources"] == ["crtsh", "anubis"]

    _run_worker_side(sessions, scan["id"], stub)

    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["status"] == "completed"
    assert detail["stats"]["findings"] == 2
    assert detail["stats"]["by_severity"] == {"info": 2}
    assert detail["error"] is None

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert len(findings) == 2
    assert {finding["host"] for finding in findings} == {"a.example.com", "b.example.com"}
    assert all(finding["template_id"] == "subdomain" for finding in findings)
    assert all(finding["severity"] == "info" for finding in findings)

    results = client.get(f"/api/v1/scans/{scan['id']}/results").json()
    assert len(results) == 4
    assert all(result["tool"] == "subfinder" for result in results)


def test_subfinder_scan_with_default_config(
    client: TestClient, sessions: SessionFactory, tmp_path: Path
) -> None:
    stub = _make_stub(tmp_path)
    project = client.post("/api/v1/projects", json={"name": "Subfinder Defaults"}).json()

    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={"tool": "subfinder", "target": {"kind": "domain", "value": "example.com"}},
    )
    assert response.status_code == 202
    scan = response.json()
    assert scan["config"]["rate_limit"] == 100
    assert scan["config"]["timeout"] == 30

    _run_worker_side(sessions, scan["id"], stub)
    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["status"] == "completed"


def test_subfinder_rejects_nuclei_config_keys(client: TestClient) -> None:
    project = client.post("/api/v1/projects", json={"name": "Subfinder Bad"}).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={
            "tool": "subfinder",
            "target": {"kind": "domain", "value": "example.com"},
            "config": {"template_ids": ["CVE-2020-1234"]},
        },
    )
    assert response.status_code == 422


def test_nuclei_rejects_subfinder_config_keys(client: TestClient) -> None:
    project = client.post("/api/v1/projects", json={"name": "Nuclei Bad"}).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={
            "tool": "nuclei",
            "target": {"kind": "url", "value": "https://example.com"},
            "config": {"sources": ["crtsh"]},
        },
    )
    assert response.status_code == 422


def test_httpx_scan_lifecycle(
    client: TestClient, sessions: SessionFactory, tmp_path: Path
) -> None:
    stub = tmp_path / "httpx-stub"
    stub.write_text(HTTPX_STUB)
    stub.chmod(0o755)
    project = client.post("/api/v1/projects", json={"name": "HTTPx Demo"}).json()

    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={
            "tool": "httpx",
            "target": {"kind": "domain", "value": "example.com"},
            "config": {"tech_detect": True, "rate_limit": 100},
        },
    )
    assert response.status_code == 202
    scan = response.json()
    assert scan["tool"] == "httpx"
    assert scan["config"]["rate_limit"] == 100

    session = sessions()
    try:
        handler = ExecuteScan(
            scans=SqlAlchemyScanRepository(session),
            adapters=lambda tool: HttpxAdapter(binary=str(stub)),
            runner=SubprocessToolRunner(),
            timeout_s=30,
        )
        handler(ScanId(uuid.UUID(scan["id"])))
    finally:
        session.close()

    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["status"] == "completed"
    assert detail["stats"]["findings"] == 2
    assert detail["stats"]["by_severity"] == {"info": 2}
    assert detail["error"] is None

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert len(findings) == 2
    assert {finding["matched_at"] for finding in findings} == {
        "https://example.com",
        "http://api.example.com",
    }

    results = client.get(f"/api/v1/scans/{scan['id']}/results").json()
    assert len(results) == 3


def test_unknown_tool_rejected(client: TestClient) -> None:
    project = client.post("/api/v1/projects", json={"name": "No Tool"}).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={"tool": "nonexistent_tool", "target": {"kind": "domain", "value": "example.com"}},
    )
    assert response.status_code == 422
