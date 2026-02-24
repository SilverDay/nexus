# v0.1.0

Initial public cut of the security-first, framework-agnostic PHP 8.2+ drop-in user management module.

## Highlights

- Implemented registration, login (username/email), email verification, password reset, remember-me token rotation, and profile management.
- Added RBAC foundations with `user`, `admin`, `super_admin`, plus admin user-management endpoints and safeguards.
- Added audit logging with request correlation support and security-relevant event capture.
- Added pluggable risk engine hooks and session security controls (session regeneration, IP/UA binding policies, session revocation).
- Added pluggable profile-field definitions with user/admin visibility and editability controls.
- Added server-rendered HTML modules and JSON API handlers for core user/admin flows.

## Security hardening included

- Enforced CSRF on authenticated JSON state-changing routes.
- Removed default password-reset token leakage from API responses.
- Added strict request-id sanitization to prevent header/log injection.
- Hardened mail header validation (CRLF rejection and invalid-address checks).
- Improved rate limiter robustness with lock-based concurrency control.
- Added profile regex safety controls and bounded field-length validation.

## Testing and CI

- Added security regression suite via `composer test:security`.
- Added non-database tests for:
  - request-id sanitization,
  - mail header hardening,
  - profile field policy safeguards.
- Added database-backed router security integration test (auto-skips without DB prerequisites).
- Added GitHub Actions workflow with:
  - fast non-database security checks,
  - MariaDB-backed security job for full router test coverage.

## Documentation

- Expanded README with setup, routes, security controls, and test/CI guidance.
- Added architecture spec updates including:
  - implementation status matrix,
  - API-to-implementation-to-route mapping,
  - acceptance checklist,
  - threat model summary.

## Notes

- This release focuses on secure foundation and extensibility.
- Phase-2 auth features (full TOTP/WebAuthn/OIDC/recovery UX) remain planned via existing extension interfaces.
