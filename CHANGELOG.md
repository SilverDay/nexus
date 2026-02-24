# Changelog

All notable changes to this project are documented in this file.

## [0.2.3] - 2026-02-24

### Fixed
- Improved configuration loading for multi-app server deployments by using app-local config discovery first.
- Added explicit config path argument support for migration runner.

### Documentation
- Clarified config resolution precedence and multi-app deployment guidance.

## [0.2.2] - 2026-02-24

### Fixed
- Packagist metadata alignment for latest published version.
- Added license metadata in package manifest and published a new patch release.

## [0.2.1] - 2026-02-24

### Fixed
- Security CI schema bootstrap in GitHub Actions.
- Database passkey payload test behavior when schema is not present in non-DB contexts.

## [0.2.0] - 2026-02-24

### Added
- Phase-2 authentication capabilities and hardening.
- File-based preformatted email templates with locale fallback.
- Configurable mail transport (null/php/smtp).
- Verification links in verification emails.
- Optional admin notification emails for new user registrations.
- Host-app integration improvements and shared PDO/config loader support.

### Security
- Expanded security regression coverage and CI matrix.
- Additional passkey, CSRF, and route protection checks.

## [0.1.0] - 2026-02-24

### Added
- Initial drop-in user module release.
