import os
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

class Config:
    # Flask secret key for session management and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')  # Fallback for development
    # Separate key used exclusively for encrypting PII in the database (emails, phones, FTP creds).
    # Set ENCRYPTION_KEY independently so SECRET_KEY can be rotated without losing encrypted data.
    # Falls back to SECRET_KEY value so existing dev environments need no change.
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', os.environ.get('SECRET_KEY', 'dev-secret-key'))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB hard limit on all request bodies

    # Database connection string, with a fallback for development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///app.db')

    # Flask-Limiter storage: set RATELIMIT_STORAGE_URI=redis://... in production
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')

    # Session cookie security
    SESSION_COOKIE_HTTPONLY = True   # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE = 'Lax' # Block cross-site request sending of cookie

    # APScheduler — disable the built-in REST API endpoint
    SCHEDULER_API_ENABLED = False

    # Flask-Mail configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 465))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')

class DevelopmentConfig(Config):
    DEBUG = True  # Enable debug mode for development
    SESSION_COOKIE_SECURE = False    # Allow HTTP in local development

class ProductionConfig(Config):
    DEBUG = False  # Disable debug mode for production
    SESSION_COOKIE_SECURE = True     # Require HTTPS for session cookie
    # Secret validation is enforced in create_app() in main.py because from_object()
    # loads class attributes without calling __init__, making __init__ guards dead code.

class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False        # Disable CSRF for test client form posts
    RATELIMIT_ENABLED = False       # Disable rate limiting in tests
    SECRET_KEY = 'test-secret-key-for-testing-only-not-production'
    ENCRYPTION_KEY = 'test-secret-key-for-testing-only-not-production'


# Dictionary to manage different configurations for different environments
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig  # Set a default configuration
}

