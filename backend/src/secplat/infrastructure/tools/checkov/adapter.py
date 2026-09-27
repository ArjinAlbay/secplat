from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pydantic import ValidationError

from secplat.domain.scanning.errors import InvalidTargetValue
from secplat.domain.scanning.records import FindingRecord
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef, ToolName
from secplat.infrastructure.tools.checkov.record import CheckovFailedCheck, CheckovReport

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "INFORMATIONAL": Severity.INFO,
}

_DEFAULT_SKIP_DIRS: tuple[str, ...] = (
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
)


@dataclass(frozen=True, slots=True)
class CheckovAdapter:
    binary: str = "checkov"
    workspace_root: str = field(default="/srv/projects")
    default_frameworks: tuple[str, ...] = ("all",)

    tool: ClassVar[ToolName] = ToolName.CHECKOV

    def build_args(self, target: TargetRef, config: Mapping[str, Any]) -> list[str]:
        path = self._resolve_path(target)
        argv = [
            self.binary,
            "-d" if os.path.isdir(path) else "-f",
            path,
            "-o",
            "json",
            "--quiet",
            "--compact",
            "--soft-fail",
        ]
        framework = config.get("framework")
        if framework and framework != "all":
            argv.extend(["--framework", str(framework)])

        configured_skip = config.get("skip_path") or []
        if isinstance(configured_skip, str):
            configured_skip = [s.strip() for s in configured_skip.split(",") if s.strip()]
        skip_paths = list(_DEFAULT_SKIP_DIRS) + list(configured_skip)
        for sp in skip_paths:
            argv.extend(["--skip-path", sp])

        return argv

    def parse_line(self, line: Mapping[str, Any]) -> FindingRecord | None:
        return None

    def parse_report(
        self, report: Mapping[str, Any] | Sequence[Mapping[str, Any]]
    ) -> tuple[FindingRecord, ...]:
        items: Sequence[Mapping[str, Any]]
        if isinstance(report, (list, tuple)):
            items = report
        elif isinstance(report, dict):
            # If multiple frameworks are evaluated, Checkov outputs a list; if single, a dict
            items = [report]
        else:
            return ()

        findings: list[FindingRecord] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                parsed = CheckovReport.model_validate(item)
            except ValidationError:
                continue

            if not parsed.results or not parsed.results.failed_checks:
                continue

            for failed in parsed.results.failed_checks:
                rec = self._to_record(failed)
                if rec:
                    findings.append(rec)

        return tuple(findings)

    def _to_record(self, check: CheckovFailedCheck) -> FindingRecord | None:
        check_id = check.check_id or "CKV_UNKNOWN"
        name = check.check_name or check_id
        sev_str = (check.severity or "").upper()
        severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

        start_line = check.file_line_range[0] if check.file_line_range else 1
        file_path = check.file_path.lstrip("/") if check.file_path else "unknown"
        matched_at = f"{file_path}:{start_line}"

        extracted: list[str] = []
        if check.resource:
            extracted.append(f"resource: {check.resource}")
        if check.guideline:
            extracted.append(f"guideline: {check.guideline}")

        return FindingRecord(
            template_id=check_id,
            name=name,
            severity=severity,
            matched_at=matched_at,
            host=file_path,
            extracted=tuple(extracted),
            raw=check.model_dump(by_alias=True, mode="json"),
        )

    def _resolve_path(self, target: TargetRef) -> str:
        if target.kind is not TargetKind.PATH:
            raise InvalidTargetValue("checkov target must be a filesystem path")
        value = target.value
        if not os.path.isabs(value):
            value = os.path.join(self.workspace_root, value)
        return value
