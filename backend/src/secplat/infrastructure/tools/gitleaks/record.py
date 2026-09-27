from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class GitleaksFinding(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    description: str = Field(default="", alias="Description")
    start_line: int = Field(default=1, alias="StartLine")
    end_line: int = Field(default=1, alias="EndLine")
    file: str = Field(default="", alias="File")
    rule_id: str = Field(default="", alias="RuleID")
    secret: str = Field(default="", alias="Secret")
    match: str = Field(default="", alias="Match")
    commit: str = Field(default="", alias="Commit")
    entropy: float = Field(default=0.0, alias="Entropy")
    fingerprint: str = Field(default="", alias="Fingerprint")
    tags: list[str] = Field(default_factory=list, alias="Tags")


class GitleaksReport(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    findings: list[GitleaksFinding] = Field(default_factory=list)
