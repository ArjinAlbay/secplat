from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CheckovGuideline(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class CheckovFailedCheck(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    check_id: str = Field(default="", alias="check_id")
    check_name: str = Field(default="", alias="check_name")
    check_result: dict[str, Any] = Field(default_factory=dict, alias="check_result")
    file_path: str = Field(default="", alias="file_path")
    file_line_range: list[int] = Field(default_factory=list, alias="file_line_range")
    resource: str = Field(default="", alias="resource")
    guideline: str | None = Field(default=None, alias="guideline")
    severity: str | None = Field(default=None, alias="severity")
    check_class: str | None = Field(default=None, alias="check_class")


class CheckovSummary(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    passed: int = 0
    failed: int = 0
    skipped: int = 0
    parsing_errors: int = 0
    resource_count: int = 0


class CheckovResults(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    failed_checks: list[CheckovFailedCheck] = Field(default_factory=list, alias="failed_checks")
    passed_checks: list[dict[str, Any]] = Field(default_factory=list, alias="passed_checks")
    skipped_checks: list[dict[str, Any]] = Field(default_factory=list, alias="skipped_checks")


class CheckovReport(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    check_type: str = Field(default="", alias="check_type")
    results: CheckovResults | None = Field(default=None, alias="results")
    summary: CheckovSummary | None = Field(default=None, alias="summary")
