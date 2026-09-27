from __future__ import annotations

import hashlib

import pytest

from secplat.domain.scanning.errors import InvalidTargetValue
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef
from secplat.infrastructure.tools.gitleaks.adapter import GitleaksAdapter


@pytest.fixture()
def adapter() -> GitleaksAdapter:
    return GitleaksAdapter(binary="gitleaks")


@pytest.fixture()
def target() -> TargetRef:
    return TargetRef(kind=TargetKind.PATH, value="/srv/projects/demo")


def test_build_args_defaults(adapter: GitleaksAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {})
    assert argv[0] == "gitleaks"
    assert argv[1] == "detect"
    assert "--source" in argv
    assert argv[argv.index("--source") + 1] == "/srv/projects/demo"
    assert "--report-format" in argv
    assert argv[argv.index("--report-format") + 1] == "json"
    assert "--report-path" in argv
    assert argv[argv.index("--report-path") + 1] == "/dev/stdout"
    assert "--exit-code" in argv
    assert argv[argv.index("--exit-code") + 1] == "0"
    assert "--no-git" not in argv
    assert "--redact" not in argv


def test_build_args_custom(adapter: GitleaksAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {"no_git": True, "redact": True})
    assert "--no-git" in argv
    assert "--redact" in argv


def test_non_path_target_rejected(adapter: GitleaksAdapter) -> None:
    with pytest.raises(InvalidTargetValue):
        adapter.build_args(TargetRef(kind=TargetKind.URL, value="https://example.com"), {})


def _report() -> list[dict]:
    return [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Token",
            "File": "config/aws.env",
            "StartLine": 12,
            "EndLine": 12,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "AKIAIOSFODNN7EXAMPLE",
            "Commit": "abc1234",
            "Author": "dev@example.com",
            "Email": "dev@example.com",
            "Date": "2026-09-01T12:00:00Z",
            "Message": "add keys",
        },
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "src/api.js",
            "StartLine": 45,
            "EndLine": 45,
            "Secret": "secret_key_123",
            "Match": "secret_key_123",
            "Commit": "",
            "Author": "",
            "Email": "",
            "Date": "",
            "Message": "",
        },
    ]


def test_parse_report_valid(adapter: GitleaksAdapter) -> None:
    records = adapter.parse_report(_report())
    assert len(records) == 2
    first = records[0]
    assert first.template_id == "aws-access-token"
    assert first.name == "AWS Access Token"
    assert first.severity is Severity.CRITICAL
    assert first.matched_at == "config/aws.env:12"
    assert first.host == "config/aws.env"
    expected = hashlib.sha256(b"aws-access-token|config/aws.env:12").hexdigest()
    assert first.fingerprint == expected
    assert records[1].severity is Severity.HIGH
    assert records[1].matched_at == "src/api.js:45"


def test_parse_report_empty(adapter: GitleaksAdapter) -> None:
    assert adapter.parse_report([]) == ()
    assert adapter.parse_report({}) == ()


def test_parse_report_dict_wrapper(adapter: GitleaksAdapter) -> None:
    records = adapter.parse_report({"results": _report()})
    assert len(records) == 2
