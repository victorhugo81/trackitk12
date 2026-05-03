import os
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_apscheduler import APScheduler
from flask_caching import Cache
from config import config

# Initialize global extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
mail = Mail()
scheduler = APScheduler()
cache = Cache()


@login_manager.user_loader
def load_user(user_id):
    from application.models import User
    return db.session.get(User, int(user_id))

def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    app = Flask(
        __name__,
        template_folder='application/templates',
        static_folder='application/static'
    )

    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'application/uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.config['UPLOAD_ATTACHMENT'] = os.path.join(app.root_path, 'application/uploads/attachments')
    os.makedirs(app.config['UPLOAD_ATTACHMENT'], exist_ok=True)

    # Use environment-specific configuration
    app.config.from_object(config[config_name])
    
    # Warn when rate limiter falls back to in-memory storage in non-debug mode.
    # Set RATELIMIT_STORAGE_URI=redis://localhost:6379 (or similar) in production.
    if not app.debug and app.config.get('RATELIMIT_STORAGE_URI', 'memory://') == 'memory://':
        import warnings
        warnings.warn(
            "Rate limiter is using in-memory storage. Limits will reset on every restart "
            "and will not be shared across workers. Set RATELIMIT_STORAGE_URI to a Redis "
            "or other persistent backend in production.",
            RuntimeWarning,
            stacklevel=2,
        )

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    scheduler.init_app(app)
    cache.init_app(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 7200})
    login_manager.login_view = "routes.login"

    migrate = Migrate(app, db)

    # Register custom Jinja2 filters
    def localtime_filter(dt, fmt='%m/%d/%Y %I:%M %p'):
        if dt is None:
            return ''
        # dt is stored as UTC (naive); convert to local system time before formatting
        import datetime as _dt
        local_dt = _dt.datetime.fromtimestamp(dt.replace(tzinfo=_dt.timezone.utc).timestamp())
        return local_dt.strftime(fmt)
    app.jinja_env.filters['localtime'] = localtime_filter

    # Register blueprint
    from application.routes import routes_blueprint
    app.register_blueprint(routes_blueprint)

    # Security headers applied to every response
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'self';"
        )
        # HSTS: only send over HTTPS — skip in debug mode to avoid breaking HTTP dev
        if not app.debug:
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains'
            )
        return response

    # Load email config from database into app config at startup
    with app.app_context():
        try:
            from application.models import Organization
            from application.utils import decrypt_mail_password
            org = db.session.get(Organization, 1)
            if org and org.mail_server:
                app.config['MAIL_SERVER'] = org.mail_server
                app.config['MAIL_PORT'] = int(org.mail_port) if org.mail_port else 587
                app.config['MAIL_USE_TLS'] = bool(org.mail_use_tls)
                app.config['MAIL_USE_SSL'] = bool(org.mail_use_ssl)
                app.config['MAIL_USERNAME'] = org.mail_username
                app.config['MAIL_PASSWORD'] = decrypt_mail_password(
                    org.mail_password or '', app.config['SECRET_KEY']
                )
                app.config['MAIL_DEFAULT_SENDER'] = org.mail_default_sender
                mail.init_app(app)
        except Exception:
            pass  # DB may not exist yet on first run / before migrations

    # Register FTP schedule from Organization if enabled
    with app.app_context():
        _register_org_ftp_schedule()

    if not scheduler.running:
        scheduler.start()

    return app

def _register_org_ftp_schedule():
    """Register (or remove) the single org-level FTP cron job based on Organization settings."""
    try:
        from application.models import Organization
        from application.scheduled_jobs import run_org_ftp_schedule
        org = db.session.get(Organization, 1)
        if org and org.ftp_schedule_enabled and org.ftp_schedule_hour is not None:
            scheduler.add_job(
                id='org_ftp_schedule',
                func=run_org_ftp_schedule,
                trigger='cron',
                day_of_week=org.ftp_schedule_days or '*',
                hour=org.ftp_schedule_hour,
                minute=org.ftp_schedule_minute or 0,
                replace_existing=True
            )
        else:
            try:
                scheduler.remove_job('org_ftp_schedule')
            except Exception:
                pass
    except Exception:
        pass  # DB not ready on first run

if __name__ == "__main__":
    # Get environment from environment variable or use default
    env = os.environ.get('FLASK_ENV', 'development')
    app = create_app(env)

    # Print all available endpoints for debugging
    with app.app_context():
        print([rule.endpoint for rule in app.url_map.iter_rules()])

    app.run(debug=app.debug)

