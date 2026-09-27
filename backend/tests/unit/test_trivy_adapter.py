from __future__ import annotations

import pytest

from secplat.domain.scanning.errors import InvalidTargetValue
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef
from secplat.infrastructure.tools.trivy.adapter import TrivyAdapter


@pytest.fixture()
def adapter() -> TrivyAdapter:
    return TrivyAdapter(binary="trivy")


@pytest.fixture()
def target() -> TargetRef:
    return TargetRef(kind=TargetKind.PATH, value="/srv/projects/demo")


def test_build_args_defaults(adapter: TrivyAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {})
    assert argv[0] == "trivy"
    assert argv[1] == "fs"
    assert argv[argv.index("--format") + 1] == "json"
    assert argv[argv.index("--scanners") + 1] == "vuln,secret,misconfig"
    assert "--quiet" in argv
    assert argv[-1] == "/srv/projects/demo"


def test_build_args_toggles(adapter: TrivyAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {"skip_db_update": True, "offline_scan": True})
    assert "--skip-db-update" in argv
    assert "--offline-scan" in argv
    assert argv[-1] == "/srv/projects/demo"


def test_build_args_always_skips_runtime_data_dirs(
    adapter: TrivyAdapter, target: TargetRef
) -> None:
    argv = adapter.build_args(target, {"skip_dirs": []})
    skip_value = argv[argv.index("--skip-dirs") + 1]
    for entry in ("mysql-data*", "postgres-data*", "node_modules", ".git"):
        assert entry in skip_value.split(",")

    argv = adapter.build_args(target, {"skip_dirs": "extra-dir"})
    skip_value = argv[argv.index("--skip-dirs") + 1]
    assert "extra-dir" in skip_value.split(",")
    assert "mysql-data*" in skip_value.split(",")


def test_non_path_target_rejected(adapter: TrivyAdapter) -> None:
    with pytest.raises(InvalidTargetValue):
        adapter.build_args(TargetRef(kind=TargetKind.DOMAIN, value="example.com"), {})


def _report() -> dict:
    return {
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
                        "Title": "lodash prototype pollution",
                    },
                    {
                        "VulnerabilityID": "CVE-2021-5678",
                        "PkgName": "axios",
                        "InstalledVersion": "0.21.0",
                        "Severity": "CRITICAL",
                    },
                ],
            },
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS001",
                        "Title": "Run as root",
                        "Severity": "HIGH",
                        "Resolution": "Add USER directive",
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Severity": "CRITICAL",
                        "Title": "AWS Access Key ID",
                        "StartLine": 3,
                        "EndLine": 3,
                    }
                ],
            },
        ],
    }


def test_parse_report_vulnerabilities(adapter: TrivyAdapter) -> None:
    records = adapter.parse_report(_report())
    assert len(records) == 4
    vuln = records[0]
    assert vuln.template_id == "CVE-2020-1234"
    assert vuln.name == "lodash prototype pollution"
    assert vuln.severity is Severity.HIGH
    assert vuln.matched_at == "package-lock.json"
    assert vuln.host == "/srv/projects/demo"
    assert vuln.extracted == ("lodash@4.17.20", "fixed: 4.17.21")
    assert vuln.raw["VulnerabilityID"] == "CVE-2020-1234"
    critical = records[1]
    assert critical.severity is Severity.CRITICAL
    assert critical.extracted == ("axios@0.21.0",)


def test_parse_report_misconfig_and_secret(adapter: TrivyAdapter) -> None:
    records = adapter.parse_report(_report())
    misconfig, secret = records[2], records[3]
    assert misconfig.template_id == "DS001"
    assert misconfig.severity is Severity.HIGH
    assert misconfig.matched_at == "Dockerfile"
    assert misconfig.extracted == ("Add USER directive",)
    assert secret.template_id == "aws-access-key-id"
    assert secret.severity is Severity.CRITICAL
    assert secret.matched_at == "Dockerfile:3"
    assert secret.extracted == ("AWS",)


def test_parse_report_unknown_severity_maps_to_unknown(adapter: TrivyAdapter) -> None:
    report = _report()
    report["Results"][0]["Vulnerabilities"][0]["Severity"] = "EXTREME"
    records = adapter.parse_report(report)
    assert records[0].severity is Severity.UNKNOWN


def test_parse_report_malformed_returns_empty(adapter: TrivyAdapter) -> None:
    assert adapter.parse_report({"Results": "oops"}) == ()
