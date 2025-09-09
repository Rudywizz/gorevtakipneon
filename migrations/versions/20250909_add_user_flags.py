"""add is_active and must_change_password to users

Revision ID: add_user_flags_20250909
Revises: ecd898b658f6
Create Date: 2025-09-09
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "add_user_flags_20250909"
down_revision = "ecd898b658f6"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = {c["name"] for c in insp.get_columns("users")}

    # SQLite'ta batch kullanmadan, tek tek ekleyelim (circular dependency önlenir)
    if "is_active" not in cols:
        if bind.dialect.name == "sqlite":
            op.add_column(
                "users",
                sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            )
        else:
            op.add_column(
                "users",
                sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            )

    if "must_change_password" not in cols:
        if bind.dialect.name == "sqlite":
            op.add_column(
                "users",
                sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.text("0")),
            )
        else:
            op.add_column(
                "users",
                sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
            )

    # (Opsiyonel) defaultları kaldırmak isterseniz burada server_default'u None yapabilirsiniz.
    # Ancak SQLite'ta ALTER COLUMN kısıtlı olduğundan genelde bırakmak daha sorunsuzdur.


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = {c["name"] for c in insp.get_columns("users")}

    # SQLite'ta drop için batch_alter_table gerekli olabilir
    if "must_change_password" in cols:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("users") as batch:
                batch.drop_column("must_change_password")
        else:
            op.drop_column("users", "must_change_password")

    if "is_active" in cols:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("users") as batch:
                batch.drop_column("is_active")
        else:
            op.drop_column("users", "is_active")
