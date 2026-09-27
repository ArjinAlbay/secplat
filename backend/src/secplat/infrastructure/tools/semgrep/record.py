from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SemgrepExtra(BaseModel):
    model_config = ConfigDict(extra="allow")

    message: str = ""
    severity: str = "INFO"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SemgrepPosition(BaseModel):
    model_config = ConfigDict(extra="allow")

    line: int = 0


class SemgrepResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    check_id: str
    path: str = ""
    start: SemgrepPosition = Field(default_factory=SemgrepPosition)
    end: SemgrepPosition = Field(default_factory=SemgrepPosition)
    extra: SemgrepExtra = Field(default_factory=SemgrepExtra)


class SemgrepReport(BaseModel):
    model_config = ConfigDict(extra="allow")

    results: list[SemgrepResult] = Field(default_factory=list)
