"""merge heads

Revision ID: f0d2f835d007
Revises: add_user_flags_20250909, ce654c3b8328
Create Date: 2025-09-09 19:04:30.836644

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f0d2f835d007'
down_revision = ('add_user_flags_20250909', 'ce654c3b8328')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
