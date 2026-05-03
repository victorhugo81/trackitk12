"""
Pytest configuration and shared fixtures for the TrackITk12 test suite.
"""
import pytest
from werkzeug.security import generate_password_hash

# Test credentials — used across all tests
ADMIN_EMAIL    = 'admin@example.com'
ADMIN_PASSWORD = 'AdminPass1!'
USER_EMAIL     = 'staff@example.com'
USER_PASSWORD  = 'StaffPass1!'


@pytest.fixture(scope='session')
def app():
    """Create the Flask application configured for testing."""
    import sys, os
    # Ensure the project root is on the path so 'main' can be imported
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from main import create_app, db as _db

    application = create_app('testing')

    with application.app_context():
        _db.create_all()
        _seed_test_data(application, _db)

    yield application

    # Teardown — stop the scheduler so it doesn't linger after the session
    with application.app_context():
        try:
            from main import scheduler
            if scheduler.running:
                scheduler.shutdown(wait=False)
        except Exception:
            pass


def _seed_test_data(application, db):
    """Insert the minimum data needed by the tests."""
    from application.models import Role, Site, User, Organization

    # Organization row (required by some dashboard queries)
    if not Organization.query.first():
        org = Organization(
            organization_name='Test District',
            site_version='1.0',
        )
        db.session.add(org)
        db.session.flush()

    # Roles
    admin_role = Role.query.filter_by(role_name='Admin').first()
    if not admin_role:
        admin_role = Role(role_name='Admin')
        db.session.add(admin_role)

    staff_role = Role.query.filter_by(role_name='Staff').first()
    if not staff_role:
        staff_role = Role(role_name='Staff')
        db.session.add(staff_role)

    db.session.flush()

    # Site
    site = Site.query.filter_by(site_name='Test School').first()
    if not site:
        site = Site(
            site_name='Test School',
            site_acronyms='TS',
            site_cds='00-000-0000000',
            site_code='TS001',
            site_address='1 Test Lane',
            site_type='Elementary',
        )
        db.session.add(site)
        db.session.flush()

    # Admin user
    from application.utils import encrypt_field, hash_email
    key = application.config['SECRET_KEY']

    if not User.query.filter_by(email_hash=hash_email(ADMIN_EMAIL, key)).first():
        admin = User(
            first_name='Admin',
            last_name='User',
            email_enc=encrypt_field(ADMIN_EMAIL, key),
            email_hash=hash_email(ADMIN_EMAIL, key),
            status='Active',
            password_hash=generate_password_hash(ADMIN_PASSWORD),
            role_id=admin_role.id,
            site_id=site.id,
        )
        db.session.add(admin)

    # Regular (non-admin) staff user
    if not User.query.filter_by(email_hash=hash_email(USER_EMAIL, key)).first():
        staff = User(
            first_name='Staff',
            last_name='User',
            email_enc=encrypt_field(USER_EMAIL, key),
            email_hash=hash_email(USER_EMAIL, key),
            status='Active',
            password_hash=generate_password_hash(USER_PASSWORD),
            role_id=staff_role.id,
            site_id=site.id,
        )
        db.session.add(staff)

    db.session.commit()


@pytest.fixture(scope='session')
def client(app):
    """A test client for the application (unauthenticated by default)."""
    return app.test_client()


def login(client, email, password):
    """Helper: POST to /login and return the response."""
    return client.post(
        '/login',
        data={'email': email, 'password': password},
        follow_redirects=True,
    )


def logout(client):
    """Helper: GET /logout."""
    return client.get('/logout', follow_redirects=True)


def _inject_user(app, client, email):
    """Set the Flask-Login session for *email* directly, bypassing the login form."""
    from application.utils import hash_email
    key = app.config['SECRET_KEY']
    with app.app_context():
        from application.models import User
        user = User.query.filter_by(email_hash=hash_email(email, key)).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True


def _clear_session(client):
    """Remove the Flask-Login session cookie."""
    with client.session_transaction() as sess:
        sess.clear()


@pytest.fixture()
def admin_client(app, client):
    """Test client pre-authenticated as the admin user (via session injection)."""
    _inject_user(app, client, ADMIN_EMAIL)
    yield client
    _clear_session(client)


@pytest.fixture()
def staff_client(app, client):
    """Test client pre-authenticated as a non-admin staff user (via session injection)."""
    _inject_user(app, client, USER_EMAIL)
    yield client
    _clear_session(client)
