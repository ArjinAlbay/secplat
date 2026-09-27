from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECPLAT_",
        env_file=("../.env", ".env", "../.env.local", ".env.local"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql+psycopg://secplat:devpass@localhost:5432/secplat"
    redis_url: str = "redis://localhost:6379/0"
    nuclei_bin: str = "nuclei"
    nuclei_template_dir: str = "/opt/nuclei-templates"
    subfinder_bin: str = "subfinder"
    semgrep_bin: str = "semgrep"
    trivy_bin: str = "trivy"
    gitleaks_bin: str = "gitleaks"
    checkov_bin: str = "checkov"
    httpx_bin: str = "httpx"
    workspace_root: str = "/srv/projects"
    scan_timeout_seconds: int = 7200
    stderr_tail_bytes: int = 4096
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "*",
    ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
