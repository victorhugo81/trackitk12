"""
Automated route tests for TrackITk12.

Coverage areas:
  - Authentication: login, logout, invalid credentials
  - Unauthenticated redirect: protected GET routes return 302 → /login
  - Admin-only routes: non-admin gets 403
  - Page smoke tests: all main pages return 200 for authenticated users
  - Bulk upload pages: GET returns 200, POST with no file returns appropriate response
"""
import io
import pytest

from tests.conftest import (
    ADMIN_EMAIL, ADMIN_PASSWORD,
    USER_EMAIL, USER_PASSWORD,
    login, logout,
)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_login_page_loads(self, client):
        rv = client.get('/login')
        assert rv.status_code == 200
        assert b'email' in rv.data.lower()

    def test_login_valid_admin(self, client):
        rv = login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
        assert rv.status_code == 200
        # Successful login redirects away from /login; final URL should not be /login
        assert rv.request.path != '/login', (
            "Login succeeded but stayed on /login page — check form validation or credentials"
        )
        logout(client)

    def test_login_valid_staff(self, client):
        rv = login(client, USER_EMAIL, USER_PASSWORD)
        assert rv.status_code == 200
        assert rv.request.path != '/login'
        logout(client)

    def test_login_wrong_password(self, client):
        rv = login(client, ADMIN_EMAIL, 'WrongPassword!')
        assert rv.status_code == 200
        # Should stay on the login page with an error message
        assert rv.request.path == '/login' or b'invalid' in rv.data.lower() \
               or b'failed' in rv.data.lower()

    def test_login_unknown_email(self, client):
        rv = login(client, 'nobody@example.org', 'Whatever1!')
        assert rv.status_code == 200
        assert rv.request.path == '/login' or b'login' in rv.data.lower()

    def test_logout_requires_login(self, client):
        """Unauthenticated logout should redirect to login."""
        rv = client.get('/logout', follow_redirects=False)
        assert rv.status_code in (301, 302)

    def test_logout_clears_session(self, admin_client):
        """After logout, a protected route should redirect to login."""
        logout(admin_client)
        rv = admin_client.get('/', follow_redirects=False)
        assert rv.status_code in (301, 302)
        assert 'login' in rv.headers.get('Location', '')


# ---------------------------------------------------------------------------
# Unauthenticated redirect — GET routes that require login
# ---------------------------------------------------------------------------

PROTECTED_GET_ROUTES = [
    '/',
    '/devices',
    '/patrons',
    '/users',
    '/sites',
    '/roles',
    '/notifications',
    '/categories',
    '/profile',
    '/organization',
    '/bulk-data-upload',
    '/bulk-upload-patrons',
    '/bulk_upload_devices',
    # Note: /bulk-upload-users and /bulk-upload-sites are POST-only routes
]


class TestUnauthenticatedRedirect:
    @pytest.mark.parametrize('path', PROTECTED_GET_ROUTES)
    def test_redirect_when_not_logged_in(self, client, path):
        """Every protected GET route must redirect an unauthenticated visitor to /login."""
        rv = client.get(path, follow_redirects=False)
        assert rv.status_code in (301, 302), (
            f"Expected redirect for {path}, got {rv.status_code}"
        )
        location = rv.headers.get('Location', '')
        assert 'login' in location, (
            f"Expected redirect to /login for {path}, got Location: {location}"
        )


# ---------------------------------------------------------------------------
# Admin-only access control (GET routes)
# ---------------------------------------------------------------------------

ADMIN_ONLY_GET_ROUTES = [
    '/users',
    '/roles',
    '/sites',
    '/notifications',
    '/categories',
    '/bulk-data-upload',
    '/bulk-upload-patrons',
    '/bulk_upload_devices',
    '/patrons',
]


class TestAdminOnlyRoutes:
    @pytest.mark.parametrize('path', ADMIN_ONLY_GET_ROUTES)
    def test_admin_can_access(self, admin_client, path):
        rv = admin_client.get(path)
        assert rv.status_code == 200, (
            f"Admin should get 200 for {path}, got {rv.status_code}"
        )

    @pytest.mark.parametrize('path', ADMIN_ONLY_GET_ROUTES)
    def test_staff_gets_403(self, staff_client, path):
        rv = staff_client.get(path)
        assert rv.status_code == 403, (
            f"Non-admin should get 403 for {path}, got {rv.status_code}"
        )

    def test_organization_page_loads(self, admin_client):
        rv = admin_client.get('/organization')
        assert rv.status_code == 200


# ---------------------------------------------------------------------------
# Page smoke tests — routes accessible by both admin and regular staff
# ---------------------------------------------------------------------------

SHARED_GET_ROUTES = [
    '/',
    '/devices',
    '/profile',
]


class TestPageSmoke:
    @pytest.mark.parametrize('path', SHARED_GET_ROUTES)
    def test_page_returns_200_for_admin(self, admin_client, path):
        rv = admin_client.get(path)
        assert rv.status_code == 200, (
            f"Expected 200 for {path}, got {rv.status_code}"
        )
        assert len(rv.data) > 0, f"Empty response body for {path}"

    @pytest.mark.parametrize('path', SHARED_GET_ROUTES)
    def test_page_returns_200_for_staff(self, staff_client, path):
        rv = staff_client.get(path)
        assert rv.status_code == 200, (
            f"Expected 200 for {path}, got {rv.status_code}"
        )


# ---------------------------------------------------------------------------
# Bulk upload pages — GET and POST
# ---------------------------------------------------------------------------

BULK_UPLOAD_GET_ROUTES = [
    '/bulk-upload-patrons',
    '/bulk_upload_devices',
]


class TestBulkUploadPages:
    @pytest.mark.parametrize('path', BULK_UPLOAD_GET_ROUTES)
    def test_bulk_upload_page_loads(self, admin_client, path):
        rv = admin_client.get(path)
        assert rv.status_code == 200, (
            f"Bulk upload page {path} returned {rv.status_code}"
        )
        assert b'upload' in rv.data.lower()

    def test_bulk_upload_patrons_post_no_file(self, admin_client):
        """POST with no file should stay on the page without a 500."""
        rv = admin_client.post(
            '/bulk-upload-patrons',
            data={},
            content_type='multipart/form-data',
            follow_redirects=True,
        )
        assert rv.status_code in (200, 400, 422), (
            f"POST with no file to /bulk-upload-patrons returned {rv.status_code}"
        )

    def test_bulk_upload_patrons_post_valid_csv(self, admin_client, app):
        """POST a minimal valid CSV — should process without a 500."""
        from application.models import Role, Site
        with app.app_context():
            role = Role.query.filter_by(role_name='Staff').first()
            site = Site.query.filter_by(site_name='Test School').first()

        csv_content = (
            'badge_id,first_name,middle_name,last_name,email,grade,status,'
            'rm_num,role_name,site_name,guardian_name,phone\r\n'
            f'TST-001,Bulk,,Upload,bulk.upload@example.com,9,Active,'
            f'101,{role.role_name},{site.site_name},,\r\n'
        )
        data = {
            'csvFile': (io.BytesIO(csv_content.encode()), 'patrons.csv'),
        }
        rv = admin_client.post(
            '/bulk-upload-patrons',
            data=data,
            content_type='multipart/form-data',
            follow_redirects=True,
        )
        assert rv.status_code == 200
        assert b'upload results' in rv.data.lower() or b'added' in rv.data.lower()

    def test_bulk_data_upload_page_loads(self, admin_client):
        """The combined bulk-data-upload (users) page should return 200."""
        rv = admin_client.get('/bulk-data-upload')
        assert rv.status_code == 200
        assert b'upload' in rv.data.lower()


# ---------------------------------------------------------------------------
# Non-existent routes
# ---------------------------------------------------------------------------

class TestNotFound:
    def test_unknown_route_returns_404(self, admin_client):
        rv = admin_client.get('/this-page-does-not-exist')
        assert rv.status_code == 404


# ---------------------------------------------------------------------------
# Static sample CSV files
# ---------------------------------------------------------------------------

class TestStaticFiles:
    def test_sample_patron_csv_available(self, client):
        rv = client.get('/static/sample_patron_upload.csv')
        assert rv.status_code == 200
        assert b'badge_id' in rv.data

    def test_sample_site_csv_available(self, client):
        rv = client.get('/static/sample_site_upload.csv')
        assert rv.status_code == 200

    def test_sample_user_csv_available(self, client):
        rv = client.get('/static/sample_user_upload.csv')
        assert rv.status_code == 200
