from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SeverityName = Literal["critical", "high", "medium", "low", "info", "unknown"]


class NucleiInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str = ""
    severity: SeverityName = "info"


class NucleiRecord(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    template_id: str = Field(alias="template-id")
    info: NucleiInfo = Field(default_factory=NucleiInfo)
    host: str = ""
    matched_at: str | None = Field(default=None, alias="matched-at")
    extracted: list[str] | None = Field(default=None, alias="extracted-results")
