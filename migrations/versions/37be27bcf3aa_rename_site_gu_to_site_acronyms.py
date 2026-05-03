"""rename site_GU to site_acronyms

Revision ID: 37be27bcf3aa
Revises: 64865d4f15ef
Create Date: 2026-03-31 18:08:00.553130

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text, inspect

# revision identifiers, used by Alembic.
revision = '37be27bcf3aa'
down_revision = '64865d4f15ef'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = inspect(conn)
    columns = [c['name'] for c in inspector.get_columns('site')]

    if 'site_GU' in columns and 'site_acronyms' not in columns:
        # Clean rename
        conn.execute(text('ALTER TABLE site CHANGE COLUMN site_GU site_acronyms VARCHAR(36) NOT NULL'))
    elif 'site_GU' in columns and 'site_acronyms' in columns:
        # Partial state from a failed previous run: copy data then drop old column
        conn.execute(text('UPDATE site SET site_acronyms = site_GU WHERE site_acronyms = "" OR site_acronyms IS NULL'))
        conn.execute(text('ALTER TABLE site DROP COLUMN site_GU'))
    # else: only site_acronyms exists — nothing to do


def downgrade():
    conn = op.get_bind()
    inspector = inspect(conn)
    columns = [c['name'] for c in inspector.get_columns('site')]

    if 'site_acronyms' in columns and 'site_GU' not in columns:
        conn.execute(text('ALTER TABLE site CHANGE COLUMN site_acronyms site_GU VARCHAR(36) NOT NULL'))
