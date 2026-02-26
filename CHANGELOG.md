# Changelog

All notable changes to this project are documented in this file.

## [0.2.4] - 2026-02-26

### Added
- Lightweight host-app demo application entrypoint at `examples/module_webapp.php` with a homepage and simple navigation.
- Restricted demo pages for user and admin areas with session and role checks.
- Dedicated file-based demo configuration template at `examples/config/module_webapp.config.php`.

### Changed
- README guidance for running and configuring the lightweight demo, including explicit file-based configuration steps.

### Fixed
- Demo config template warning cleanup in `examples/config/module.config.php`.

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
