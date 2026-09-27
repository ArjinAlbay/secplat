from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

TargetKindName = Literal["domain", "ip", "cidr", "url", "path"]


class TargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: TargetKindName
    value: Annotated[str, Field(min_length=1, max_length=2048)]


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(min_length=1, max_length=200)]
    description: str | None = Field(default=None, max_length=2000)
