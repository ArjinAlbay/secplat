from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from secplat.application.scanning.commands import ExecuteScan
from secplat.domain.scanning.value_objects import ScanId
from secplat.infrastructure.config import get_settings
from secplat.infrastructure.persistence.repositories import SqlAlchemyScanRepository
from secplat.infrastructure.tools.checkov.adapter import CheckovAdapter
from secplat.infrastructure.tools.nuclei.adapter import NucleiAdapter
from secplat.infrastructure.tools.semgrep.adapter import SemgrepAdapter
from secplat.infrastructure.tools.subprocess_runner import SubprocessToolRunner
from secplat.infrastructure.tools.trivy.adapter import TrivyAdapter
from tests.conftest import SessionFactory

CHECKOV_STUB = """#!/usr/bin/env python3
import json

print("checkov: scanning /srv/projects/demo ...", flush=True)
report = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_20",
                "check_name": "Ensure S3 bucket has bucket policy",
                "file_path": "/main.tf",
                "file_line_range": [1, 10],
                "resource": "aws_s3_bucket.mybucket",
                "severity": "HIGH",
            },
            {
                "check_id": "CKV_AWS_18",
                "check_name": "Ensure S3 access logging enabled",
                "file_path": "/s3.tf",
                "file_line_range": [5, 12],
                "resource": "aws_s3_bucket.logging",
                "severity": "LOW",
            },
        ],
    },
    "summary": {"passed": 0, "failed": 2},
}
print(json.dumps(report, indent=2))
"""

SEMGREP_STUB = """#!/usr/bin/env python3
import json

print("semgrep: scanning /srv/projects/demo with config {auto} ...", flush=True)
report = {
    "results": [
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "app/auth.py",
            "start": {"line": 10},
            "end": {"line": 12},
            "extra": {"message": "Hardcoded password", "severity": "ERROR"},
        },
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "app/auth.py",
            "start": {"line": 10},
            "end": {"line": 12},
            "extra": {"message": "Hardcoded password", "severity": "ERROR"},
        },
        {
            "check_id": "python.lang.maintainability.is-string-compare",
            "path": "app/util.py",
            "start": {"line": 3},
            "end": {"line": 3},
            "extra": {"message": "String comparison", "severity": "WARNING"},
        },
    ],
    "errors": [],
}
print(json.dumps(report, indent=2))
"""

TRIVY_STUB = """#!/usr/bin/env python3
import json

print("trivy: downloading db ... skipped", flush=True)
report = {
    "SchemaVersion": 2,
    "ArtifactName": "/srv/projects/demo",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2020-1234",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                },
                {
                    "VulnerabilityID": "CVE-2020-1234",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                },
            ],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {"ID": "DS001", "Title": "Run as root", "Severity": "HIGH"}
            ],
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key ID",
                    "StartLine": 3,
                }
            ],
        },
    ],
}
print(json.dumps(report, indent=2))
"""


def _make_stub(tmp_path: Path, name: str, script: str) -> Path:
    stub = tmp_path / name
    stub.write_text(script)
    stub.chmod(0o755)
    return stub


def _run_worker_side(sessions: SessionFactory, scan_id: str, adapter: Any) -> None:
    session: Session = sessions()
    try:
        handler = ExecuteScan(
            scans=SqlAlchemyScanRepository(session),
            adapters=lambda tool: adapter,
            runner=SubprocessToolRunner(),
            timeout_s=30,
        )
        handler(ScanId(uuid.UUID(scan_id)))
    finally:
        session.close()


def test_semgrep_scan_lifecycle(
    client: TestClient, sessions: SessionFactory, tmp_path: Path
) -> None:
    stub = _make_stub(tmp_path, "semgrep-stub", SEMGREP_STUB)
    project = client.post("/api/v1/projects", json={"name": "Semgrep Demo"}).json()

    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={"tool": "semgrep", "target": {"kind": "path", "value": "/srv/projects/demo"}},
    )
    assert response.status_code == 202
    scan = response.json()
    assert scan["status"] == "queued"
    assert scan["tool"] == "semgrep"
    assert scan["target"] == {"kind": "path", "value": "/srv/projects/demo"}
    assert scan["config"] == {"config": "auto"}

    _run_worker_side(sessions, scan["id"], SemgrepAdapter(binary=str(stub)))

    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["status"] == "completed"
    assert detail["stats"]["findings"] == 2
    assert detail["stats"]["by_severity"] == {"high": 1, "medium": 1}
    assert detail["error"] is None

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert len(findings) == 2
    assert {finding["severity"] for finding in findings} == {"high", "medium"}
    assert all(finding["host"].endswith(".py") for finding in findings)

    results = client.get(f"/api/v1/scans/{scan['id']}/results").json()
    assert len(results) == 1
    assert results[0]["tool"] == "semgrep"


def test_trivy_scan_lifecycle(
    client: TestClient, sessions: SessionFactory, tmp_path: Path
) -> None:
    stub = _make_stub(tmp_path, "trivy-stub", TRIVY_STUB)
    project = client.post("/api/v1/projects", json={"name": "Trivy Demo"}).json()

    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={
            "tool": "trivy",
            "target": {"kind": "path", "value": "/srv/projects/demo"},
            "config": {"skip_db_update": True},
        },
    )
    assert response.status_code == 202
    scan = response.json()
    assert scan["tool"] == "trivy"
    assert scan["config"]["scanners"] == ["vuln", "secret", "misconfig"]

    _run_worker_side(sessions, scan["id"], TrivyAdapter(binary=str(stub)))

    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["status"] == "completed"
    assert detail["stats"]["findings"] == 3
    assert detail["stats"]["by_severity"] == {"high": 2, "critical": 1}
    assert detail["error"] is None

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert len(findings) == 3
    assert {finding["template_id"] for finding in findings} == {
        "CVE-2020-1234",
        "DS001",
        "aws-access-key-id",
    }

    results = client.get(f"/api/v1/scans/{scan['id']}/results").json()
    assert len(results) == 1
    assert results[0]["tool"] == "trivy"


def test_relative_path_target_resolved_to_workspace_root(client: TestClient) -> None:
    project = client.post("/api/v1/projects", json={"name": "Bad Path"}).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={"tool": "semgrep", "target": {"kind": "path", "value": "relative/app"}},
    )
    assert response.status_code == 202
    expected_root = get_settings().workspace_root
    assert response.json()["target"]["value"] == f"{expected_root}/relative/app"


def test_semgrep_rejects_nuclei_config_keys(client: TestClient) -> None:
    project = client.post("/api/v1/projects", json={"name": "Semgrep Bad"}).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={
            "tool": "semgrep",
            "target": {"kind": "path", "value": "/srv/projects/demo"},
            "config": {"severity": ["high"]},
        },
    )
    assert response.status_code == 422


def test_checkov_scan_lifecycle(
    client: TestClient, sessions: SessionFactory, tmp_path: Path
) -> None:
    stub = _make_stub(tmp_path, "checkov-stub", CHECKOV_STUB)
    project = client.post("/api/v1/projects", json={"name": "Checkov Demo"}).json()

    response = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={
            "tool": "checkov",
            "target": {"kind": "path", "value": "/srv/projects/demo"},
            "config": {"framework": "terraform"},
        },
    )
    assert response.status_code == 202
    scan = response.json()
    assert scan["tool"] == "checkov"
    assert scan["config"]["framework"] == "terraform"

    _run_worker_side(sessions, scan["id"], CheckovAdapter(binary=str(stub)))

    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["status"] == "completed"
    assert detail["stats"]["findings"] == 2
    assert detail["stats"]["by_severity"] == {"high": 1, "low": 1}
    assert detail["error"] is None

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()
    assert len(findings) == 2
    assert {finding["template_id"] for finding in findings} == {
        "CKV_AWS_20",
        "CKV_AWS_18",
    }

    results = client.get(f"/api/v1/scans/{scan['id']}/results").json()
    assert len(results) == 1
    assert results[0]["tool"] == "checkov"


def test_nuclei_path_target_fails_with_clear_error(
    client: TestClient, sessions: SessionFactory
) -> None:
    project = client.post("/api/v1/projects", json={"name": "Nuclei Path"}).json()
    scan = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        json={"tool": "nuclei", "target": {"kind": "path", "value": "/srv/projects/demo"}},
    ).json()

    _run_worker_side(
        sessions, scan["id"], NucleiAdapter(binary="nuclei", template_dir="/tmp/tpl")
    )

    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["status"] == "failed"
    assert "InvalidTargetValue" in detail["error"]

