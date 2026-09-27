"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-09-15
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

scan_status_type = postgresql.ENUM(
    "pending",
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
    name="scan_status",
    create_type=False,
)
tool_name_type = postgresql.ENUM("nuclei", name="tool_name", create_type=False)
target_kind_type = postgresql.ENUM(
    "domain", "ip", "cidr", "url", name="target_kind", create_type=False
)
severity_type = postgresql.ENUM(
    "critical", "high", "medium", "low", "info", "unknown", name="severity", create_type=False
)


def _create_enums() -> None:
    bind = op.get_bind()
    sa.Enum(
        "pending", "queued", "running", "completed", "failed", "cancelled", name="scan_status"
    ).create(bind, checkfirst=True)
    sa.Enum("nuclei", name="tool_name").create(bind, checkfirst=True)
    sa.Enum("domain", "ip", "cidr", "url", name="target_kind").create(bind, checkfirst=True)
    sa.Enum(
        "critical", "high", "medium", "low", "info", "unknown", name="severity"
    ).create(bind, checkfirst=True)


def upgrade() -> None:
    _create_enums()

    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "targets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", target_kind_type, nullable=False),
        sa.Column("value", sa.String(2048), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("project_id", "kind", "value", name="uq_targets_project_kind_value"),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.Uuid(), sa.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("parent_scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("target_kind", target_kind_type, nullable=False),
        sa.Column("target_value", sa.String(2048), nullable=False),
        sa.Column("tool", tool_name_type, nullable=False),
        sa.Column("status", scan_status_type, nullable=False),
        sa.Column("task_id", sa.String(255)),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("stats", postgresql.JSONB()),
        sa.Column("error", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_scans_project_tool_status", "scans", ["project_id", "tool", "status"])
    op.create_index("ix_scans_parent", "scans", ["parent_scan_id"])

    op.create_table(
        "scan_results",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tool", sa.String(32), nullable=False),
        sa.Column("raw", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_scan_results_scan_id", "scan_results", ["scan_id"])
    op.create_index(
        "ix_scan_results_raw_gin",
        "scan_results",
        ["raw"],
        postgresql_using="gin",
        postgresql_ops={"raw": "jsonb_path_ops"},
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("severity", severity_type, nullable=False),
        sa.Column("template_id", sa.String(255), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("matched_at", sa.Text(), nullable=False),
        sa.Column("host", sa.Text(), nullable=False),
        sa.Column("extracted", postgresql.JSONB()),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
    )
    op.create_index(
        "ix_findings_project_severity_status", "findings", ["project_id", "severity", "status"]
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_index("ix_scan_results_raw_gin", table_name="scan_results")
    op.drop_table("scan_results")
    op.drop_table("scans")
    op.drop_table("targets")
    op.drop_table("projects")
    bind = op.get_bind()
    sa.Enum(name="severity").drop(bind, checkfirst=True)
    sa.Enum(name="target_kind").drop(bind, checkfirst=True)
    sa.Enum(name="tool_name").drop(bind, checkfirst=True)
    sa.Enum(name="scan_status").drop(bind, checkfirst=True)
