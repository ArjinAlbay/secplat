from __future__ import annotations

import hashlib

import pytest

from secplat.domain.scanning.errors import ConfigNotAllowed
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef
from secplat.infrastructure.tools.nuclei.adapter import NucleiAdapter


@pytest.fixture()
def adapter() -> NucleiAdapter:
    return NucleiAdapter(binary="nuclei", template_dir="/tmp/tpl")


@pytest.fixture()
def target() -> TargetRef:
    return TargetRef(kind=TargetKind.URL, value="https://example.com")


def test_forced_flags_present(adapter: NucleiAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {"rate_limit": 42})
    assert argv[0] == "nuclei"
    for flag in ("-jsonl", "-silent", "-nc", "-duc", "-ni"):
        assert flag in argv
    assert "-lna" not in argv
    assert argv[argv.index("-ud") + 1] == "/tmp/tpl"
    assert argv[argv.index("-u") + 1] == "https://example.com"
    assert argv[argv.index("-rl") + 1] == "42"


def test_unknown_config_key_rejected(adapter: NucleiAdapter, target: TargetRef) -> None:
    with pytest.raises(ConfigNotAllowed):
        adapter.build_args(target, {"exec": "rm -rf /"})  # noqa: S108


def test_severity_tags_and_omit_raw(adapter: NucleiAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(
        target,
        {"severity": ["critical", "high"], "tags": ["cve"], "omit_raw": True},
    )
    assert argv[argv.index("-severity") + 1] == "critical,high"
    assert argv[argv.index("-tags") + 1] == "cve"
    assert "-or" in argv


def test_advanced_nuclei_config_flags(adapter: NucleiAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(
        target,
        {
            "exclude_tags": ["dos"],
            "exclude_template_ids": ["cve-1234"],
            "custom_headers": ["Authorization: Bearer test", "X-Custom: 1"],
            "stop_at_first_match": True,
            "restrict_local_network": True,
        },
    )
    assert argv[argv.index("-etags") + 1] == "dos"
    assert argv[argv.index("-eid") + 1] == "cve-1234"
    assert argv.count("-H") == 2
    assert argv[argv.index("-H") + 1] == "Authorization: Bearer test"
    assert "-sfm" in argv
    assert "-lna" in argv


def test_parse_line_valid(adapter: NucleiAdapter) -> None:
    line = {
        "template-id": "CVE-2020-1234",
        "info": {"name": "Test Vuln", "severity": "high"},
        "host": "https://example.com",
        "matched-at": "https://example.com/x",
        "extracted-results": ["secret"],
    }
    record = adapter.parse_line(line)
    assert record is not None
    assert record.template_id == "CVE-2020-1234"
    assert record.severity is Severity.HIGH
    assert record.matched_at == "https://example.com/x"
    assert record.extracted == ("secret",)
    assert record.fingerprint == hashlib.sha256(b"CVE-2020-1234|https://example.com/x").hexdigest()


def test_parse_line_malformed_returns_none(adapter: NucleiAdapter) -> None:
    assert adapter.parse_line({"no-template-id": True}) is None
