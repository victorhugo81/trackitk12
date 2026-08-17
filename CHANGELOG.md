# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.6] - 2026-08-16

### Added
- About modal, opened by clicking the footer copyright notice, showing the app name, description, version, and copyright year.

### Changed
- Sidebar logo is now centered.
- About modal's version number is now read from this changelog at runtime instead of being hardcoded in the template.


## [1.0.5] - 2026-08-09

### Security
- Authorization checks now consistently use role-name based checks (`is_admin` / `is_tech_role`) instead of hard-coded role IDs, closing gaps that let non-admins change roles, reset other users' passwords, or edit other admin/tech accounts.
- Patron search endpoint now requires authentication with an appropriate role.
- Login no longer leaks whether an email is registered via response-timing differences.
- Added per-request CSP nonce for inline scripts and tightened `script-src` accordingly.


## [1.0.4] - 2026-08-09

### Changed
- Refreshed dashboard and navigation theme colors and spacing.


## [1.0.3] - 2026-06-17

### Fixed
- Export button no longer broken by the Content Security Policy (script/img sources adjusted to allow the export library and generated file downloads).


## [1.0.2] - 2026-06-17

### Security
- Rate limited the change-password endpoint.
- Removed user emails from application logs; sensitive log messages now reference user IDs instead.
- Restricted role changes on the edit-user form to admins only.

### Added
- Hard 16 MB limit on request body size.


## [1.0.1] - 2026-06-17

### Added
- Dedicated `ENCRYPTION_KEY` setting for encrypting stored PII (emails, phone numbers, mail credentials), separate from `SECRET_KEY` so the session/CSRF key can be rotated without breaking decryption of existing data.
- Startup validation that rejects default/placeholder `SECRET_KEY` and `ENCRYPTION_KEY` values in production.


## [1.0.0] - 2026-05-02

### Added
- Initial project structure and application scaffolding.
- User authentication (login/logout).
- Models for users, roles, sites, tickets, and notifications.
- CRUD routes and forms for all models.
- Base HTML templates and includes (header, footer, nav).
- Static files structure: CSS, JS, images, uploads.


---