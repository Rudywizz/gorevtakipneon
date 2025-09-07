"""add email to users

Revision ID: ecd898b658f6
Revises: 256ac890c711
Create Date: 2025-09-07 02:40:57.172964
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ecd898b658f6'
down_revision = '256ac890c711'
branch_labels = None
depends_on = None


def upgrade():
    # 1) Kolonu NULL kabul edecek şekilde ekle (mevcut kayıtlar patlamasın)
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(length=200), nullable=True))

    # 2) NULL olmayan e-postalarda benzersizliği sağlayan partial unique index
    #    Hem Postgres hem SQLite bu sözdizimini destekliyor.
    conn = op.get_bind()
    dialect = conn.dialect.name

    if dialect in ("postgresql", "sqlite"):
        op.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_unique "
            "ON users(email) WHERE email IS NOT NULL;"
        )
    else:
        # Diğer veritabanları için (gerekirse) düz unique index — 
        # (Çoklu NULL’a izin verenler zaten sorun çıkarmaz)
        op.create_index(
            "ix_users_email_unique",
            "users",
            ["email"],
            unique=True
        )


def downgrade():
    # 1) Index’i kaldır
    conn = op.get_bind()
    dialect = conn.dialect.name

    if dialect in ("postgresql", "sqlite"):
        op.execute("DROP INDEX IF EXISTS ix_users_email_unique;")
    else:
        op.drop_index("ix_users_email_unique", table_name="users")

    # 2) Kolonu kaldır
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('email')
