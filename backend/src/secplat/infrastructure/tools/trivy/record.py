from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TrivyVulnerability(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    vulnerability_id: str = Field(alias="VulnerabilityID")
    pkg_name: str = Field(default="", alias="PkgName")
    installed_version: str = Field(default="", alias="InstalledVersion")
    fixed_version: str = Field(default="", alias="FixedVersion")
    severity: str = Field(default="UNKNOWN", alias="Severity")
    title: str = Field(default="", alias="Title")
    description: str = Field(default="", alias="Description")
    primary_url: str = Field(default="", alias="PrimaryURL")


class TrivyMisconfiguration(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    id: str = Field(alias="ID")
    title: str = Field(default="", alias="Title")
    severity: str = Field(default="UNKNOWN", alias="Severity")
    description: str = Field(default="", alias="Description")
    resolution: str = Field(default="", alias="Resolution")
    primary_url: str = Field(default="", alias="PrimaryURL")


class TrivySecret(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    rule_id: str = Field(alias="RuleID")
    category: str = Field(default="", alias="Category")
    severity: str = Field(default="UNKNOWN", alias="Severity")
    title: str = Field(default="", alias="Title")
    start_line: int = Field(default=0, alias="StartLine")
    end_line: int = Field(default=0, alias="EndLine")


class TrivyResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    target: str = Field(default="", alias="Target")
    vulnerabilities: list[TrivyVulnerability] | None = Field(default=None, alias="Vulnerabilities")
    misconfigurations: list[TrivyMisconfiguration] | None = Field(
        default=None, alias="Misconfigurations"
    )
    secrets: list[TrivySecret] | None = Field(default=None, alias="Secrets")


class TrivyReport(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    artifact_name: str = Field(default="", alias="ArtifactName")
    artifact_type: str = Field(default="", alias="ArtifactType")
    results: list[TrivyResult] = Field(default_factory=list, alias="Results")
