from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pydantic import ValidationError

from secplat.domain.scanning.errors import InvalidTargetValue
from secplat.domain.scanning.records import FindingRecord
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef, ToolName
from secplat.infrastructure.tools.semgrep.record import SemgrepReport

_SEVERITIES = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}

_PRESET_CONFIGS = {
    "auto",
    "p/default",
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/secrets",
    "p/python",
    "p/javascript",
    "p/typescript",
}


@dataclass(frozen=True, slots=True)
class SemgrepAdapter:
    binary: str = "semgrep"
    default_config: str = "auto"
    workspace_root: str = field(default="/srv/projects")

    tool: ClassVar[ToolName] = ToolName.SEMGREP

    def build_args(self, target: TargetRef, config: Mapping[str, Any]) -> list[str]:
        rules = str(config.get("config") or self.default_config)
        argv = [self.binary, "--config", rules]
        if rules != "auto":
            argv += ["--metrics", "off"]
        argv += ["--json", self._resolve_path(target)]
        return argv

    def parse_line(self, line: Mapping[str, Any]) -> FindingRecord | None:
        return None

    def parse_report(self, report: Mapping[str, Any]) -> tuple[FindingRecord, ...]:
        try:
            parsed = SemgrepReport.model_validate(report)
        except ValidationError:
            return ()
        return tuple(
            FindingRecord(
                template_id=result.check_id,
                name=result.extra.message or result.check_id,
                severity=_SEVERITIES.get(result.extra.severity.upper(), Severity.UNKNOWN),
                matched_at=f"{result.path}:{result.start.line}",
                host=result.path,
                extracted=(f"lines {result.start.line}-{result.end.line}",),
                raw=result.model_dump(mode="json"),
            )
            for result in parsed.results
        )

    def _resolve_path(self, target: TargetRef) -> str:
        if target.kind is not TargetKind.PATH:
            raise InvalidTargetValue("semgrep target must be a filesystem path")
        value = target.value
        if not os.path.isabs(value):
            value = os.path.join(self.workspace_root, value)
        return value
