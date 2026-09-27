from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import NewType

from secplat.domain.scanning.errors import InvalidTargetValue

ProjectId = NewType("ProjectId", uuid.UUID)
TargetId = NewType("TargetId", uuid.UUID)
ScanId = NewType("ScanId", uuid.UUID)


class ScanStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self.value in ("completed", "failed", "cancelled")


class ToolName(StrEnum):
    NUCLEI = "nuclei"
    SUBFINDER = "subfinder"
    SEMGREP = "semgrep"
    TRIVY = "trivy"
    GITLEAKS = "gitleaks"
    CHECKOV = "checkov"
    HTTPX = "httpx"


class TargetKind(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    PATH = "path"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class TargetRef:
    kind: TargetKind
    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise InvalidTargetValue("target value must not be empty")
        if self.kind is TargetKind.URL and not self.value.startswith(("http://", "https://")):
            raise InvalidTargetValue("url target must start with http:// or https://")
        if self.kind is TargetKind.PATH and (
            not self.value.startswith("/") or "\x00" in self.value
        ):
            raise InvalidTargetValue("path target must be an absolute filesystem path")
