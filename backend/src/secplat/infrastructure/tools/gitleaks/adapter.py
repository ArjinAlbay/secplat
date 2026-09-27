from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pydantic import ValidationError

from secplat.domain.scanning.errors import InvalidTargetValue
from secplat.domain.scanning.records import FindingRecord
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef, ToolName
from secplat.infrastructure.tools.gitleaks.record import GitleaksFinding, GitleaksReport

_CRITICAL_RULES = {
    "aws-access-token",
    "private-key",
    "gcp-api-key",
    "azure-ad-client-secret",
    "github-pat",
    "slack-bot-token",
    "stripe-api-token",
}


@dataclass(frozen=True, slots=True)
class GitleaksAdapter:
    binary: str = "gitleaks"
    workspace_root: str = field(default="/srv/projects")

    tool: ClassVar[ToolName] = ToolName.GITLEAKS

    def build_args(self, target: TargetRef, config: Mapping[str, Any]) -> list[str]:
        path = self._resolve_path(target)
        argv = [
            self.binary,
            "detect",
            "--source",
            path,
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
            "--exit-code",
            "0",
            "--no-banner",
        ]
        if config.get("no_git"):
            argv.append("--no-git")
        if config.get("redact"):
            argv.append("--redact")
        return argv

    def parse_line(self, line: Mapping[str, Any]) -> FindingRecord | None:
        try:
            finding = GitleaksFinding.model_validate(line)
        except ValidationError:
            return None
        return self._to_record(finding)

    def parse_report(
        self, report: Mapping[str, Any] | Sequence[Mapping[str, Any]]
    ) -> tuple[FindingRecord, ...]:
        if isinstance(report, (list, tuple)):
            records = []
            for item in report:
                if isinstance(item, dict):
                    rec = self.parse_line(item)
                    if rec:
                        records.append(rec)
            return tuple(records)

        if "RuleID" in report or "rule_id" in report:
            try:
                finding = GitleaksFinding.model_validate(report)
                record = self._to_record(finding)
                return (record,) if record else ()
            except ValidationError:
                return ()

        raw_results = report.get("results") or report.get("findings")
        if isinstance(raw_results, (list, tuple)):
            records = []
            for item in raw_results:
                if isinstance(item, dict):
                    rec = self.parse_line(item)
                    if rec:
                        records.append(rec)
            return tuple(records)

        try:
            parsed = GitleaksReport.model_validate(report)
        except ValidationError:
            return ()

        records = [self._to_record(f) for f in parsed.findings]
        return tuple(r for r in records if r is not None)

    def _to_record(self, finding: GitleaksFinding) -> FindingRecord | None:
        rule_id = finding.rule_id or "secret-detected"
        name = finding.description or rule_id
        rule_lower = rule_id.lower()
        if any(cr in rule_lower for cr in _CRITICAL_RULES):
            severity = Severity.CRITICAL
        else:
            severity = Severity.HIGH

        matched_at = f"{finding.file}:{finding.start_line}" if finding.file else rule_id
        extracted_info = []
        if finding.commit:
            extracted_info.append(f"commit: {finding.commit[:10]}")
        if finding.entropy > 0:
            extracted_info.append(f"entropy: {finding.entropy:.2f}")

        return FindingRecord(
            template_id=rule_id,
            name=name,
            severity=severity,
            matched_at=matched_at,
            host=finding.file,
            extracted=tuple(extracted_info),
            raw=finding.model_dump(by_alias=True, mode="json"),
        )

    def _resolve_path(self, target: TargetRef) -> str:
        if target.kind is not TargetKind.PATH:
            raise InvalidTargetValue("gitleaks target must be a filesystem path")
        value = target.value
        if not os.path.isabs(value):
            value = os.path.join(self.workspace_root, value)
        return value
