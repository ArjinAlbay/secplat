from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class HttpxRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str = Field(default="")
    input: str = Field(default="")
    host: str = Field(default="")
    port: str = Field(default="")
    scheme: str = Field(default="")
    status_code: int = Field(default=0, alias="status_code")
    title: str = Field(default="")
    webserver: str = Field(default="")
    content_type: str = Field(default="", alias="content_type")
    content_length: int = Field(default=0, alias="content_length")
    tech: list[str] = Field(default_factory=list)
    method: str = Field(default="GET")
    chain_status_codes: list[int] = Field(default_factory=list, alias="chain_status_codes")
    final_url: str = Field(default="", alias="final_url")
    failed: bool = Field(default=False)
