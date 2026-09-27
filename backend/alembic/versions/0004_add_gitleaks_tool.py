from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE tool_name ADD VALUE IF NOT EXISTS 'gitleaks'")


def downgrade() -> None:
    pass
