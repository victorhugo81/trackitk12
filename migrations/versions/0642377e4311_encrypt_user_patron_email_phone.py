"""encrypt user patron email phone

Revision ID: 0642377e4311
Revises: 3772e0ac4ae5
Create Date: 2026-04-08 20:18:23.465409

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text
from sqlalchemy.dialects import mysql
import hashlib, base64, hmac

# revision identifiers, used by Alembic.
revision = '0642377e4311'
down_revision = '3772e0ac4ae5'
branch_labels = None
depends_on = None


def _get_fernet(secret_key):
    from cryptography.fernet import Fernet
    key = base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode()).digest())
    return Fernet(key)


def _encrypt(value, secret_key):
    if not value:
        return ''
    return _get_fernet(secret_key).encrypt(value.encode()).decode()


def _hash_email(email, secret_key):
    return hmac.new(secret_key.encode(), email.strip().lower().encode(), 'sha256').hexdigest()


def upgrade():
    from flask import current_app
    key = current_app.config['SECRET_KEY']
    conn = op.get_bind()

    # 1. Add new columns as nullable so existing rows don't fail NOT NULL
    op.add_column('patron', sa.Column('email_enc', sa.String(length=512), nullable=True))
    op.add_column('patron', sa.Column('email_hash', sa.String(length=64), nullable=True))
    op.add_column('patron', sa.Column('phone_enc', sa.String(length=512), nullable=True))
    op.add_column('user', sa.Column('email_enc', sa.String(length=512), nullable=True))
    op.add_column('user', sa.Column('email_hash', sa.String(length=64), nullable=True))

    # 2. Encrypt existing data
    users = conn.execute(text('SELECT id, email FROM `user`')).fetchall()
    for u in users:
        enc = _encrypt(u.email, key)
        h   = _hash_email(u.email, key)
        conn.execute(
            text('UPDATE `user` SET email_enc=:enc, email_hash=:h WHERE id=:id'),
            {'enc': enc, 'h': h, 'id': u.id}
        )

    patrons = conn.execute(text('SELECT id, email, phone FROM patron')).fetchall()
    for p in patrons:
        enc = _encrypt(p.email, key)
        h   = _hash_email(p.email, key)
        phone_enc = _encrypt(p.phone, key) if p.phone else None
        conn.execute(
            text('UPDATE patron SET email_enc=:enc, email_hash=:h, phone_enc=:penc WHERE id=:id'),
            {'enc': enc, 'h': h, 'penc': phone_enc, 'id': p.id}
        )

    # 3. Drop old unique indexes on email before altering columns or dropping them
    op.drop_index('email', table_name='user')
    op.drop_index('email', table_name='patron')

    # 4. Make new columns NOT NULL and add unique/index constraints
    op.alter_column('user', 'email_enc', nullable=False, existing_type=sa.String(512))
    op.alter_column('user', 'email_hash', nullable=False, existing_type=sa.String(64))
    op.create_index('ix_user_email_hash', 'user', ['email_hash'], unique=True)

    op.alter_column('patron', 'email_enc', nullable=False, existing_type=sa.String(512))
    op.alter_column('patron', 'email_hash', nullable=False, existing_type=sa.String(64))
    op.create_index('ix_patron_email_hash', 'patron', ['email_hash'], unique=True)

    # 5. Drop old columns
    op.drop_column('user', 'email')
    op.drop_column('patron', 'email')
    op.drop_column('patron', 'phone')


def downgrade():
    # Add back old columns as nullable, then make NOT NULL after populating would require
    # decryption — for simplicity we restore as nullable VARCHAR.
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', mysql.VARCHAR(length=120), nullable=True))
        batch_op.drop_index('ix_user_email_hash')
        batch_op.drop_column('email_hash')
        batch_op.drop_column('email_enc')

    with op.batch_alter_table('patron', schema=None) as batch_op:
        batch_op.add_column(sa.Column('phone', mysql.VARCHAR(length=20), nullable=True))
        batch_op.add_column(sa.Column('email', mysql.VARCHAR(length=120), nullable=True))
        batch_op.drop_index('ix_patron_email_hash')
        batch_op.drop_column('phone_enc')
        batch_op.drop_column('email_hash')
        batch_op.drop_column('email_enc')
