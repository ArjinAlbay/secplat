from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import urlsplit

from pydantic import ValidationError

from secplat.domain.scanning.errors import ConfigNotAllowed, InvalidTargetValue
from secplat.domain.scanning.records import FindingRecord
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef, ToolName
from secplat.infrastructure.tools.subfinder.record import SubfinderRecord

ALLOWED_CONFIG_KEYS = frozenset(
    {
        "sources",
        "exclude_sources",
        "all_sources",
        "recursive",
        "rate_limit",
        "timeout",
        "max_time",
        "exclude_ip",
    }
)

FORCED_ARGS = ("-oJ", "-silent", "-nc", "-duc", "-cs")


@dataclass(frozen=True, slots=True)
class SubfinderAdapter:
    binary: str = "subfinder"

    tool: ClassVar[ToolName] = ToolName.SUBFINDER

    def build_args(self, target: TargetRef, config: Mapping[str, Any]) -> list[str]:
        unknown = set(config) - ALLOWED_CONFIG_KEYS
        if unknown:
            raise ConfigNotAllowed(f"unsupported config keys: {sorted(unknown)}")
        argv = [self.binary, *FORCED_ARGS, "-d", _domain(target)]
        if sources := config.get("sources"):
            argv += ["-s", ",".join(sources)]
        if exclude_sources := config.get("exclude_sources"):
            argv += ["-es", ",".join(exclude_sources)]
        if config.get("all_sources"):
            argv += ["-all"]
        if config.get("recursive"):
            argv += ["-recursive"]
        argv += [
            "-rl",
            str(config.get("rate_limit", 100)),
            "-timeout",
            str(config.get("timeout", 30)),
            "-max-time",
            str(config.get("max_time", 10)),
        ]
        if config.get("exclude_ip"):
            argv += ["-ei"]
        return argv

    def parse_line(self, line: Mapping[str, Any]) -> FindingRecord | None:
        try:
            record = SubfinderRecord.model_validate(line)
        except ValidationError:
            return None
        return FindingRecord(
            template_id="subdomain",
            name=record.host,
            severity=Severity.INFO,
            matched_at="",
            host=record.host,
            extracted=tuple(record.sources),
            raw=dict(line),
        )

    def parse_report(self, report: Mapping[str, Any]) -> tuple[FindingRecord, ...]:
        record = self.parse_line(report)
        return () if record is None else (record,)


def _domain(target: TargetRef) -> str:
    if target.kind is TargetKind.DOMAIN:
        return target.value
    if target.kind is TargetKind.URL:
        if host := urlsplit(target.value).hostname:
            return host
    raise InvalidTargetValue("subfinder target must be a domain or url")
