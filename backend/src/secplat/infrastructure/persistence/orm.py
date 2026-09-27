from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from secplat.domain.scanning.value_objects import ScanStatus, Severity, TargetKind, ToolName


class Base(DeclarativeBase):
    pass


JSONType = JSON().with_variant(postgresql.JSONB(), "postgresql")
BigIntegerPK = BigInteger().with_variant(Integer(), "sqlite")


def _enum_values(enum_cls: type[Enum]) -> list[str]:
    return [member.value for member in enum_cls]


def _pg_enum(enum_cls: type[Enum], name: str) -> SAEnum:
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=True,
        values_callable=_enum_values,
        length=16,
    )


target_kind_type = _pg_enum(TargetKind, "target_kind")
tool_name_type = _pg_enum(ToolName, "tool_name")
scan_status_type = _pg_enum(ScanStatus, "scan_status")
severity_type = _pg_enum(Severity, "severity")


class ProjectORM(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TargetORM(Base):
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("project_id", "kind", "value", name="uq_targets_project_kind_value"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[TargetKind] = mapped_column(target_kind_type)
    value: Mapped[str] = mapped_column(String(2048))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ScanORM(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_project_tool_status", "project_id", "tool", "status"),
        Index("ix_scans_parent", "parent_scan_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    parent_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id"), nullable=True
    )
    target_kind: Mapped[TargetKind] = mapped_column(target_kind_type)
    target_value: Mapped[str] = mapped_column(String(2048))
    tool: Mapped[ToolName] = mapped_column(tool_name_type)
    status: Mapped[ScanStatus] = mapped_column(scan_status_type)
    task_id: Mapped[str | None] = mapped_column(String(255))
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    stats: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ScanResultORM(Base):
    __tablename__ = "scan_results"
    __table_args__ = (Index("ix_scan_results_scan_id", "scan_id"),)

    id: Mapped[int] = mapped_column(BigIntegerPK, primary_key=True, autoincrement=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    tool: Mapped[str] = mapped_column(String(32))
    raw: Mapped[dict[str, Any]] = mapped_column(JSONType)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class FindingORM(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
        Index("ix_findings_project_severity_status", "project_id", "severity", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    severity: Mapped[Severity] = mapped_column(severity_type)
    template_id: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(Text)
    matched_at: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(Text)
    extracted: Mapped[list[str] | None] = mapped_column(JSONType)
    fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="open")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
