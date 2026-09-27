"""add subfinder to tool_name enum

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-15
"""
from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE tool_name ADD VALUE IF NOT EXISTS 'subfinder'")


def downgrade() -> None:
    pass
