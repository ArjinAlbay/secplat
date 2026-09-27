from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from secplat.domain.scanning.value_objects import Severity


@dataclass(frozen=True, slots=True)
class FindingRecord:
    template_id: str
    name: str
    severity: Severity
    matched_at: str
    host: str
    extracted: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        key = f"{self.template_id}|{self.matched_at or self.host}"
        return hashlib.sha256(key.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class FindingView:
    severity: Severity
    template_id: str
    name: str
    matched_at: str
    host: str
    extracted: tuple[str, ...] = ()
    status: str = "open"
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ScanResultView:
    tool: str
    raw: Mapping[str, Any]
    created_at: datetime
