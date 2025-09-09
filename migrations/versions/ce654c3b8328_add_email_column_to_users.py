"""add email column to users

Revision ID: ce654c3b8328
Revises: ecd898b658f6
Create Date: 2025-09-07 03:18:53.203990
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ce654c3b8328'
down_revision = 'ecd898b658f6'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)

    # 1) Kolon yoksa ekle (unique ILAVE ETME!)
    cols = {c["name"] for c in insp.get_columns("users")}
    if "email" not in cols:
        with op.batch_alter_table("users") as batch_op:
            batch_op.add_column(sa.Column("email", sa.String(length=200), nullable=True))

    # 2) Eski (varsa) index/constraint temizliği
    idx_names = {ix["name"] for ix in insp.get_indexes("users")}
    if "ix_users_email_unique" in idx_names:
        op.drop_index("ix_users_email_unique", table_name="users")

    # 3) İsimli UNIQUE index oluştur
    if "ix_users_email" not in idx_names:
        op.create_index("ix_users_email", "users", ["email"], unique=True)


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)

    # 1) UNIQUE index'i kaldır
    idx_names = {ix["name"] for ix in insp.get_indexes("users")}
    if "ix_users_email" in idx_names:
        op.drop_index("ix_users_email", table_name="users")

    # 2) Kolonu kaldır (varsa)
    cols = {c["name"] for c in insp.get_columns("users")}
    if "email" in cols:
        with op.batch_alter_table("users") as batch_op:
            batch_op.drop_column("email")
