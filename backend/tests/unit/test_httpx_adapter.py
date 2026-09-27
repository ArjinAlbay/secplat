from __future__ import annotations

import hashlib

import pytest

from secplat.domain.scanning.errors import ConfigNotAllowed, InvalidTargetValue
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef
from secplat.infrastructure.tools.httpx.adapter import HttpxAdapter


@pytest.fixture()
def adapter() -> HttpxAdapter:
    return HttpxAdapter(binary="httpx")


@pytest.fixture()
def target() -> TargetRef:
    return TargetRef(kind=TargetKind.DOMAIN, value="example.com")


def test_forced_flags_and_defaults(adapter: HttpxAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {})
    assert argv[0] == "httpx"
    for flag in ("-json", "-silent", "-nc", "-duc", "-sc", "-cl", "-title", "-server"):
        assert flag in argv
    assert "-td" in argv
    assert argv[argv.index("-u") + 1] == "example.com"
    assert argv[argv.index("-threads") + 1] == "50"
    assert argv[argv.index("-rl") + 1] == "150"
    assert argv[argv.index("-timeout") + 1] == "10"


def test_custom_options(adapter: HttpxAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(
        target,
        {
            "tech_detect": False,
            "follow_redirects": True,
            "ports": [80, 443, 8080],
            "path": "/admin",
            "threads": 100,
            "rate_limit": 300,
            "timeout": 15,
        },
    )
    assert "-td" not in argv
    assert "-fr" in argv
    assert argv[argv.index("-p") + 1] == "80,443,8080"
    assert argv[argv.index("-path") + 1] == "/admin"
    assert argv[argv.index("-threads") + 1] == "100"


def test_path_target_rejected(adapter: HttpxAdapter) -> None:
    with pytest.raises(InvalidTargetValue):
        adapter.build_args(TargetRef(kind=TargetKind.PATH, value="/srv/projects/demo"), {})


def test_unknown_config_rejected(adapter: HttpxAdapter, target: TargetRef) -> None:
    with pytest.raises(ConfigNotAllowed):
        adapter.build_args(target, {"invalid_key": 123})


def test_parse_line_valid(adapter: HttpxAdapter) -> None:
    line = {
        "url": "https://example.com",
        "input": "example.com",
        "host": "example.com",
        "port": "443",
        "scheme": "https",
        "status_code": 200,
        "title": "Example Domain",
        "webserver": "nginx/1.18.0",
        "tech": ["Nginx", "HSTS"],
        "content_length": 1256,
    }
    record = adapter.parse_line(line)
    assert record is not None
    assert record.template_id == "http-service"
    assert record.severity is Severity.INFO
    assert record.matched_at == "https://example.com"
    assert record.host == "example.com"
    assert "[200] Example Domain (nginx/1.18.0)" in record.name
    assert "status: 200" in record.extracted
    assert "server: nginx/1.18.0" in record.extracted
    assert "tech: Nginx, HSTS" in record.extracted
    assert record.fingerprint == hashlib.sha256(b"http-service|https://example.com").hexdigest()


def test_parse_line_failed_or_empty_returns_none(adapter: HttpxAdapter) -> None:
    assert adapter.parse_line({"failed": True, "url": "https://bad.com"}) is None
    assert adapter.parse_line({"status_code": 500}) is None
    assert adapter.parse_line({"invalid": "json"}) is None
