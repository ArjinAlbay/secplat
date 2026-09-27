from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

from pydantic import ValidationError

from secplat.domain.scanning.errors import ConfigNotAllowed, InvalidTargetValue
from secplat.domain.scanning.records import FindingRecord
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef, ToolName
from secplat.infrastructure.tools.httpx.record import HttpxRecord

ALLOWED_CONFIG_KEYS = frozenset(
    {
        "status_code",
        "tech_detect",
        "follow_redirects",
        "title",
        "threads",
        "rate_limit",
        "timeout",
        "ports",
        "path",
    }
)

FORCED_ARGS = ("-json", "-silent", "-nc", "-duc", "-sc", "-cl", "-title", "-server")


@dataclass(frozen=True, slots=True)
class HttpxAdapter:
    binary: str = "httpx"

    tool: ClassVar[ToolName] = ToolName.HTTPX

    def build_args(self, target: TargetRef, config: Mapping[str, Any]) -> list[str]:
        if target.kind is TargetKind.PATH:
            raise InvalidTargetValue("httpx target must be a network target, not a path")
        unknown = set(config) - ALLOWED_CONFIG_KEYS
        if unknown:
            raise ConfigNotAllowed(f"unsupported config keys: {sorted(unknown)}")

        argv = [self.binary, *FORCED_ARGS, "-u", target.value]

        if config.get("tech_detect", True):
            argv.append("-td")
        if config.get("follow_redirects"):
            argv.append("-fr")

        if ports := config.get("ports"):
            if isinstance(ports, (list, tuple)):
                argv.extend(["-p", ",".join(str(p) for p in ports)])
            elif isinstance(ports, str):
                argv.extend(["-p", ports])

        if path := config.get("path"):
            argv.extend(["-path", str(path)])

        argv.extend(
            [
                "-threads",
                str(config.get("threads", 50)),
                "-rl",
                str(config.get("rate_limit", 150)),
                "-timeout",
                str(config.get("timeout", 10)),
            ]
        )
        return argv

    def parse_line(self, line: Mapping[str, Any]) -> FindingRecord | None:
        try:
            record = HttpxRecord.model_validate(line)
        except ValidationError:
            return None

        if record.failed or not record.url:
            return None

        status_part = f"[{record.status_code}]" if record.status_code else ""
        title_part = f" {record.title}" if record.title else ""
        server_part = f" ({record.webserver})" if record.webserver else ""
        name = f"{status_part}{title_part}{server_part}".strip() or record.url

        extracted: list[str] = []
        if record.status_code:
            extracted.append(f"status: {record.status_code}")
        if record.title:
            extracted.append(f"title: {record.title}")
        if record.webserver:
            extracted.append(f"server: {record.webserver}")
        if record.tech:
            extracted.append(f"tech: {', '.join(record.tech)}")
        if record.content_length:
            extracted.append(f"length: {record.content_length}")

        return FindingRecord(
            template_id="http-service",
            name=name,
            severity=Severity.INFO,
            matched_at=record.url,
            host=record.host or record.input or record.url,
            extracted=tuple(extracted),
            raw=dict(line),
        )

    def parse_report(self, report: Mapping[str, Any]) -> tuple[FindingRecord, ...]:
        record = self.parse_line(report)
        return () if record is None else (record,)
