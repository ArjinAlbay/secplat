"""add semgrep/trivy tools and path target kind

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-18
"""
from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE tool_name ADD VALUE IF NOT EXISTS 'semgrep'")
    op.execute("ALTER TYPE tool_name ADD VALUE IF NOT EXISTS 'trivy'")
    op.execute("ALTER TYPE target_kind ADD VALUE IF NOT EXISTS 'path'")


def downgrade() -> None:
    pass
