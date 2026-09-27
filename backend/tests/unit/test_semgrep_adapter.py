from __future__ import annotations

import hashlib

import pytest

from secplat.domain.scanning.errors import InvalidTargetValue
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef
from secplat.infrastructure.tools.semgrep.adapter import SemgrepAdapter


@pytest.fixture()
def adapter() -> SemgrepAdapter:
    return SemgrepAdapter(binary="semgrep")


@pytest.fixture()
def target() -> TargetRef:
    return TargetRef(kind=TargetKind.PATH, value="/srv/projects/demo")


def test_build_args_defaults(adapter: SemgrepAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {})
    assert argv[0] == "semgrep"
    assert argv[argv.index("--config") + 1] == "auto"
    assert "--json" in argv
    assert "--metrics" not in argv
    assert argv[-1] == "/srv/projects/demo"


def test_config_override(adapter: SemgrepAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {"config": "p/owasp-top-ten"})
    assert argv[argv.index("--config") + 1] == "p/owasp-top-ten"
    assert argv[argv.index("--metrics") + 1] == "off"
    assert argv[-1] == "/srv/projects/demo"


def test_non_path_target_rejected(adapter: SemgrepAdapter) -> None:
    with pytest.raises(InvalidTargetValue):
        adapter.build_args(TargetRef(kind=TargetKind.URL, value="https://example.com"), {})


def _report() -> dict:
    return {
        "results": [
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


def test_parse_report_valid(adapter: SemgrepAdapter) -> None:
    records = adapter.parse_report(_report())
    assert len(records) == 2
    first = records[0]
    assert first.template_id == "python.lang.security.audit.hardcoded-password"
    assert first.name == "Hardcoded password"
    assert first.severity is Severity.HIGH
    assert first.matched_at == "app/auth.py:10"
    assert first.host == "app/auth.py"
    assert first.extracted == ("lines 10-12",)
    expected = hashlib.sha256(
        b"python.lang.security.audit.hardcoded-password|app/auth.py:10"
    ).hexdigest()
    assert first.fingerprint == expected
    assert records[1].severity is Severity.MEDIUM
    assert records[1].matched_at == "app/util.py:3"


def test_parse_report_empty_results(adapter: SemgrepAdapter) -> None:
    assert adapter.parse_report({"results": []}) == ()


def test_parse_report_malformed_returns_empty(adapter: SemgrepAdapter) -> None:
    assert adapter.parse_report({"results": "oops"}) == ()
