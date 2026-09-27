from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class SubfinderRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    host: str
    input: str = ""
    sources: list[str] = Field(default_factory=list)
