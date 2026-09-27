from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

from pydantic import ValidationError

from secplat.domain.scanning.errors import ConfigNotAllowed, InvalidTargetValue
from secplat.domain.scanning.records import FindingRecord
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef, ToolName
from secplat.infrastructure.tools.nuclei.record import NucleiRecord

ALLOWED_CONFIG_KEYS = frozenset(
    {
        "severity",
        "tags",
        "exclude_tags",
        "template_ids",
        "exclude_template_ids",
        "custom_headers",
        "stop_at_first_match",
        "rate_limit",
        "concurrency",
        "timeout",
        "omit_raw",
        "no_interactsh",
        "restrict_local_network",
    }
)

FORCED_ARGS = ("-jsonl", "-silent", "-nc", "-duc")


@dataclass(frozen=True, slots=True)
class NucleiAdapter:
    binary: str = "nuclei"
    template_dir: str = "/opt/nuclei-templates"

    tool: ClassVar[ToolName] = ToolName.NUCLEI

    def build_args(self, target: TargetRef, config: Mapping[str, Any]) -> list[str]:
        if target.kind is TargetKind.PATH:
            raise InvalidTargetValue("nuclei target must be a network target, not a path")
        unknown = set(config) - ALLOWED_CONFIG_KEYS
        if unknown:
            raise ConfigNotAllowed(f"unsupported config keys: {sorted(unknown)}")
        argv = [
            self.binary,
            *FORCED_ARGS,
            "-ud",
            self.template_dir,
            "-u",
            target.value,
        ]
        if severity := config.get("severity"):
            argv += ["-severity", ",".join(severity)]
        if tags := config.get("tags"):
            argv += ["-tags", ",".join(tags)]
        if exclude_tags := config.get("exclude_tags"):
            argv += ["-etags", ",".join(exclude_tags)]
        if template_ids := config.get("template_ids"):
            argv += ["-id", ",".join(template_ids)]
        if exclude_template_ids := config.get("exclude_template_ids"):
            argv += ["-eid", ",".join(exclude_template_ids)]
        if custom_headers := config.get("custom_headers"):
            for header in custom_headers:
                argv += ["-H", header]
        if config.get("stop_at_first_match"):
            argv += ["-sfm"]
        argv += [
            "-rl",
            str(config.get("rate_limit", 150)),
            "-c",
            str(config.get("concurrency", 25)),
            "-timeout",
            str(config.get("timeout", 10)),
        ]
        if config.get("omit_raw"):
            argv += ["-or"]
        if config.get("no_interactsh", True):
            argv += ["-ni"]
        if config.get("restrict_local_network", False):
            argv += ["-lna"]
        return argv

    def parse_line(self, line: Mapping[str, Any]) -> FindingRecord | None:
        try:
            record = NucleiRecord.model_validate(line)
        except ValidationError:
            return None
        return FindingRecord(
            template_id=record.template_id,
            name=record.info.name,
            severity=Severity(record.info.severity),
            matched_at=record.matched_at or record.host,
            host=record.host,
            extracted=tuple(record.extracted or ()),
            raw=dict(line),
        )

    def parse_report(self, report: Mapping[str, Any]) -> tuple[FindingRecord, ...]:
        record = self.parse_line(report)
        return () if record is None else (record,)
