from __future__ import annotations

import hashlib

import pytest

from secplat.domain.scanning.errors import ConfigNotAllowed, InvalidTargetValue
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef
from secplat.infrastructure.tools.subfinder.adapter import SubfinderAdapter


@pytest.fixture()
def adapter() -> SubfinderAdapter:
    return SubfinderAdapter(binary="subfinder")


@pytest.fixture()
def target() -> TargetRef:
    return TargetRef(kind=TargetKind.DOMAIN, value="example.com")


def test_forced_flags_present(adapter: SubfinderAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {"rate_limit": 42})
    assert argv[0] == "subfinder"
    for flag in ("-oJ", "-silent", "-nc", "-duc", "-cs"):
        assert flag in argv
    assert argv[argv.index("-d") + 1] == "example.com"
    assert argv[argv.index("-rl") + 1] == "42"


def test_unknown_config_key_rejected(adapter: SubfinderAdapter, target: TargetRef) -> None:
    with pytest.raises(ConfigNotAllowed):
        adapter.build_args(target, {"proxy": "http://evil"})


def test_sources_and_toggles(adapter: SubfinderAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(
        target,
        {
            "sources": ["crtsh", "anubis"],
            "exclude_sources": ["zoomeyeapi"],
            "all_sources": True,
            "recursive": True,
            "exclude_ip": True,
        },
    )
    assert argv[argv.index("-s") + 1] == "crtsh,anubis"
    assert argv[argv.index("-es") + 1] == "zoomeyeapi"
    assert "-all" in argv
    assert "-recursive" in argv
    assert "-ei" in argv


def test_url_target_uses_hostname(adapter: SubfinderAdapter) -> None:
    argv = adapter.build_args(
        TargetRef(kind=TargetKind.URL, value="https://example.com:8443/app"), {}
    )
    assert argv[argv.index("-d") + 1] == "example.com"


def test_ip_target_rejected(adapter: SubfinderAdapter) -> None:
    with pytest.raises(InvalidTargetValue):
        adapter.build_args(TargetRef(kind=TargetKind.IP, value="93.184.216.34"), {})


def test_parse_line_valid(adapter: SubfinderAdapter) -> None:
    line = {"host": "sub.example.com", "input": "example.com", "sources": ["crtsh", "anubis"]}
    record = adapter.parse_line(line)
    assert record is not None
    assert record.template_id == "subdomain"
    assert record.severity is Severity.INFO
    assert record.name == "sub.example.com"
    assert record.host == "sub.example.com"
    assert record.extracted == ("crtsh", "anubis")
    assert record.raw["input"] == "example.com"
    assert record.fingerprint == hashlib.sha256(b"subdomain|sub.example.com").hexdigest()


def test_parse_line_malformed_returns_none(adapter: SubfinderAdapter) -> None:
    assert adapter.parse_line({"no-host": True}) is None
