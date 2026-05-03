from main import db  # Import db from main.py where it's initialized
from flask_login import UserMixin
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc)


class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    organization_name = db.Column(db.String(100), nullable=False)
    site_version = db.Column(db.String(100), nullable=False)
    organization_logo = db.Column(db.String(100), nullable=True)
    # Flask-Mail configuration
    mail_server = db.Column(db.String(255), nullable=True)
    mail_port = db.Column(db.Integer, nullable=True)
    mail_use_tls = db.Column(db.Boolean, default=False, nullable=True)
    mail_use_ssl = db.Column(db.Boolean, default=False, nullable=True)
    mail_username = db.Column(db.String(255), nullable=True)
    mail_password = db.Column(db.String(255), nullable=True)
    mail_default_sender = db.Column(db.String(255), nullable=True)
    # FTP configuration (host, username, password stored encrypted)
    ftp_host_enc = db.Column(db.String(512), nullable=True)
    ftp_port = db.Column(db.Integer, default=21, nullable=True)
    ftp_username_enc = db.Column(db.String(512), nullable=True)
    ftp_password_enc = db.Column(db.String(512), nullable=True)
    ftp_path = db.Column(db.String(512), nullable=True)
    ftp_use_tls = db.Column(db.Boolean, default=False, nullable=True)
    # FTP schedule
    ftp_schedule_enabled = db.Column(db.Boolean, default=False, nullable=True)
    ftp_schedule_hour    = db.Column(db.Integer, nullable=True)
    ftp_schedule_minute  = db.Column(db.Integer, default=0, nullable=True)
    ftp_schedule_days       = db.Column(db.String(50), default='*', nullable=True)  # '*' or 'mon,tue,...'
    ftp_schedule_start_date = db.Column(db.Date, nullable=True)
    ftp_schedule_stop_date  = db.Column(db.Date, nullable=True)
    ftp_last_run_at      = db.Column(db.DateTime, nullable=True)
    ftp_last_run_status  = db.Column(db.String(20), nullable=True)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    msg_name = db.Column(db.String(100), unique=True, nullable=False)
    msg_content = db.Column(db.String(255), nullable=False)
    msg_status = db.Column(db.String(10), nullable=False)



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=False)
    email_enc  = db.Column(db.String(512), nullable=False, default='')
    email_hash = db.Column(db.String(64),  nullable=False, unique=True, index=True, default='')
    status = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    rm_num = db.Column(db.String(45), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('site.id', ondelete='CASCADE'), nullable=False)

    @property
    def email(self):
        from flask import current_app
        from .utils import decrypt_field
        return decrypt_field(self.email_enc or '', current_app.config['SECRET_KEY'])

    @email.setter
    def email(self, value):
        from flask import current_app
        from .utils import encrypt_field, hash_email
        key = current_app.config['SECRET_KEY']
        self.email_enc  = encrypt_field(value or '', key)
        self.email_hash = hash_email(value or '', key)

    def get_full_name(self):
        return f"{self.first_name} {self.middle_name or ''} {self.last_name}".strip()
    @property
    def is_admin(self):
        return self.role and self.role.role_name.lower() == "admin"
    @property
    def is_tech_role(self):
        return self.role and self.role.role_name.lower() in ["specialist", "technician"]



class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    role_name = db.Column(db.String(50), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)
    patrons = db.relationship('Patron', backref='role', lazy=True)



class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    site_name = db.Column(db.String(100), nullable=False, unique=True)
    site_acronyms = db.Column(db.String(36), nullable=False, unique=True)
    site_cds = db.Column(db.String(100), nullable=False, unique=True)
    site_code = db.Column(db.String(100), nullable=False, unique=True)
    site_address = db.Column(db.String(100), nullable=False)
    site_type = db.Column(db.String(100), nullable=False)
    # Relationships
    users = db.relationship('User', backref='site', lazy=True)
    patrons = db.relationship('Patron', backref='site', lazy=True)
    devices = db.relationship('Device', back_populates='site', lazy=True)



class Patron(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    badge_id = db.Column(db.String(50), nullable=False, unique=True)
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=False)
    email_enc  = db.Column(db.String(512), nullable=False, default='')
    email_hash = db.Column(db.String(64),  nullable=False, unique=True, index=True, default='')
    grade = db.Column(db.String(45), nullable=False)
    status = db.Column(db.String(120), nullable=False)
    rm_num = db.Column(db.String(45), nullable=False)
    guardian_name = db.Column(db.String(100), nullable=True)
    phone_enc = db.Column(db.String(512), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('site.id', ondelete='CASCADE'), nullable=False)

    @property
    def email(self):
        from flask import current_app
        from .utils import decrypt_field
        return decrypt_field(self.email_enc or '', current_app.config['SECRET_KEY'])

    @email.setter
    def email(self, value):
        from flask import current_app
        from .utils import encrypt_field, hash_email
        key = current_app.config['SECRET_KEY']
        self.email_enc  = encrypt_field(value or '', key)
        self.email_hash = hash_email(value or '', key)

    @property
    def phone(self):
        from flask import current_app
        from .utils import decrypt_field
        return decrypt_field(self.phone_enc or '', current_app.config['SECRET_KEY'])

    @phone.setter
    def phone(self, value):
        from flask import current_app
        from .utils import encrypt_field
        self.phone_enc = encrypt_field(value or '', current_app.config['SECRET_KEY']) if value else None

    # Relationship: one patron -> many devices
    devices = db.relationship("Device", foreign_keys="Device.assigned_to_id", back_populates="assigned_to", lazy=True)
    def get_patron_name(self):
        return f"{self.first_name} {self.middle_name or ''} {self.last_name}".strip()


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category_name = db.Column(db.String(100), nullable=False, unique=True)
    # Relationships: one category has many devices
    devices = db.relationship('Device', back_populates='category', lazy=True)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    serial_num = db.Column(db.String(100), nullable=False, unique=True)
    device_tag = db.Column(db.String(100), nullable=True)
    brand_name = db.Column(db.String(100), nullable=False)
    model_name = db.Column(db.String(100), nullable=False)
    device_condition = db.Column(db.String(45), nullable=False, index=True)
    chkout_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=_utcnow)
    return_at = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    in_repair = db.Column(db.Boolean, default=False, nullable=False)
    repair_date = db.Column(db.DateTime, nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('patron.id'))
    site_id = db.Column(db.Integer, db.ForeignKey('site.id'), nullable=False)
    # NEW: track who created the record
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Relationships
    category = db.relationship('Category', back_populates='devices')
    assigned_to = db.relationship('Patron', foreign_keys=[assigned_to_id], back_populates='devices')
    created_by = db.relationship('User', foreign_keys=[user_id], backref='created_devices')
    site = db.relationship('Site', back_populates='devices')
    repair_comments = db.relationship('DeviceComment', back_populates='device', order_by='DeviceComment.created_at.desc()', lazy=True)
    history = db.relationship('DeviceHistory', back_populates='device', order_by='DeviceHistory.changed_at.desc()', lazy=True)


class DeviceComment(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    # Relationships
    device = db.relationship('Device', back_populates='repair_comments')
    author = db.relationship('User', foreign_keys=[user_id])


class DeviceHistory(db.Model):
    """Audit trail — one row per changed field per save."""
    __tablename__ = 'device_history'
    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id     = db.Column(db.Integer, db.ForeignKey('device.id', ondelete='CASCADE'), nullable=False, index=True)
    changed_by_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    changed_at    = db.Column(db.DateTime, default=_utcnow, nullable=False)
    action        = db.Column(db.String(20), nullable=False)   # 'created' | 'updated'
    field_name    = db.Column(db.String(50),  nullable=True)   # None for 'created' action
    old_value     = db.Column(db.String(512), nullable=True)
    new_value     = db.Column(db.String(512), nullable=True)

    device     = db.relationship('Device', back_populates='history')
    changed_by = db.relationship('User', foreign_keys=[changed_by_id])


class BulkUploadLog(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    total_records = db.Column(db.Integer, default=0)
    users_added = db.Column(db.Integer, default=0)
    users_updated = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='success')
    error_message = db.Column(db.Text, nullable=True)

    uploader = db.relationship('User', foreign_keys=[uploaded_by_id])