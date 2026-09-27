from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pydantic import ValidationError

from secplat.domain.scanning.errors import InvalidTargetValue
from secplat.domain.scanning.records import FindingRecord
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef, ToolName
from secplat.infrastructure.tools.trivy.record import TrivyReport, TrivyVulnerability


@dataclass(frozen=True, slots=True)
class TrivyAdapter:
    binary: str = "trivy"
    default_scanners: tuple[str, ...] = ("vuln", "secret", "misconfig")
    workspace_root: str = field(default="/srv/projects")
    default_skip_dirs: tuple[str, ...] = (
        ".git",
        "node_modules",
        "bower_components",
        "mysql-data*",
        "postgres-data*",
        "redis-data*",
        "vendor",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
    )

    tool: ClassVar[ToolName] = ToolName.TRIVY

    def build_args(self, target: TargetRef, config: Mapping[str, Any]) -> list[str]:
        scanners = tuple(config.get("scanners") or self.default_scanners)
        argv = [
            self.binary,
            "fs",
            "--format",
            "json",
            "--scanners",
            ",".join(scanners),
            "--quiet",
        ]
        configured_skip_raw = config.get("skip_dirs") or []
        if isinstance(configured_skip_raw, str):
            configured_skip_raw = configured_skip_raw.split(",")
        configured_skip = tuple(part.strip() for part in configured_skip_raw if part.strip())
        skip_dirs = ",".join((*self.default_skip_dirs, *configured_skip))
        if skip_dirs:
            argv.extend(["--skip-dirs", skip_dirs])
        if config.get("skip_db_update"):
            argv.append("--skip-db-update")
        if config.get("offline_scan"):
            argv.append("--offline-scan")
        argv.append(self._resolve_path(target))
        return argv

    def parse_line(self, line: Mapping[str, Any]) -> FindingRecord | None:
        return None

    def parse_report(self, report: Mapping[str, Any]) -> tuple[FindingRecord, ...]:
        try:
            parsed = TrivyReport.model_validate(report)
        except ValidationError:
            return ()
        findings: list[FindingRecord] = []
        for result in parsed.results:
            for vuln in result.vulnerabilities or ():
                findings.append(
                    FindingRecord(
                        template_id=vuln.vulnerability_id,
                        name=vuln.title or f"{vuln.pkg_name}@{vuln.installed_version}",
                        severity=_severity(vuln.severity),
                        matched_at=result.target,
                        host=parsed.artifact_name,
                        extracted=_pkg_versions(vuln),
                        raw=vuln.model_dump(by_alias=True, mode="json"),
                    )
                )
            for misconfig in result.misconfigurations or ():
                findings.append(
                    FindingRecord(
                        template_id=misconfig.id,
                        name=misconfig.title or misconfig.id,
                        severity=_severity(misconfig.severity),
                        matched_at=result.target,
                        host=parsed.artifact_name,
                        extracted=(misconfig.resolution,) if misconfig.resolution else (),
                        raw=misconfig.model_dump(by_alias=True, mode="json"),
                    )
                )
            for secret in result.secrets or ():
                findings.append(
                    FindingRecord(
                        template_id=secret.rule_id,
                        name=secret.title or secret.rule_id,
                        severity=_severity(secret.severity),
                        matched_at=f"{result.target}:{secret.start_line}",
                        host=parsed.artifact_name,
                        extracted=(secret.category,) if secret.category else (),
                        raw=secret.model_dump(by_alias=True, mode="json"),
                    )
                )
        return tuple(findings)

    def _resolve_path(self, target: TargetRef) -> str:
        if target.kind is not TargetKind.PATH:
            raise InvalidTargetValue("trivy target must be a filesystem path")
        value = target.value
        if not os.path.isabs(value):
            value = os.path.join(self.workspace_root, value)
        return value


def _severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.UNKNOWN


def _pkg_versions(vuln: TrivyVulnerability) -> tuple[str, ...]:
    extracted = [f"{vuln.pkg_name}@{vuln.installed_version}"]
    if vuln.fixed_version:
        extracted.append(f"fixed: {vuln.fixed_version}")
    return tuple(extracted)
