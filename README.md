# Nexus Drop-In User Module

Security-first, framework-agnostic PHP 8.2+ user management module for MariaDB/MySQL.

## Current milestone

This repository now contains a first-working scaffold with:

- PSR-4 package setup (`composer.json`)
- Idempotent schema migration runner (`src/Database/MigrationRunner.php`)
- Initial security-focused schema (`src/Database/Migrations/InitialSchemaMigration.php`)
- Core auth flow foundation (`src/Service/AuthService.php`)
- PDO-backed audit logging (`src/Audit/PdoAuditLogger.php`)
- PDO-backed rate limiting (`src/RateLimit/PdoRateLimiter.php`)
- JSON handler example (`src/Controller/AuthJsonController.php`)
- Minimal demo router (`examples/minimal_router.php`)
- Pluggable profile-field KV storage (`user_profile_fields`) and profile endpoints

## Architecture snapshot

- `Nexus\DropInUser\Database`: connection factory, migration contracts, migration runner.
- `Nexus\DropInUser\Repository`: persistence layer interfaces and PDO implementations.
- `Nexus\DropInUser\Service`: auth orchestration and domain services.
- `Nexus\DropInUser\Security`: password hashing, token hashing/generation, CSRF, security headers.
- `Nexus\DropInUser\Audit`: auditable event persistence with context sanitization.
- `Nexus\DropInUser\Controller`: mountable controller/handler classes (router-agnostic).

## Local setup

1. Install dependencies:

	```bash
	composer install
	```

2. Configure database env vars:

	```bash
	export NEXUS_DB_DSN='mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4'
	export NEXUS_DB_USER='root'
	export NEXUS_DB_PASS=''
	```

3. Run migrations:

	```bash
	php migrations/run.php
	```

4. Start demo router:

	```bash
	php -S 127.0.0.1:8080 examples/minimal_router.php
	```

5. Run security regression tests:

	```bash
	composer test:security
	```

## Example endpoints

- `POST /register` with `username`, `email`, `realname`, `password`, optional `profile_fields[key]=value`
- `POST /login` with `identifier` (username or email), `password`, optional `remember_me=1`
- `POST /verify-email` with `token`
- `POST /password-reset/request` with `identifier`
- `POST /password-reset/confirm` with `token`, `new_password`
- `GET /profile` (authenticated) to read current profile and custom fields
- `POST /profile` (authenticated) with `realname`, optional `profile_fields[key]=value` to update (`csrf_token` or `X-CSRF-Token` required)

### Admin endpoints (require authenticated admin/super_admin session)

- `GET /admin/users?q=&limit=&offset=`
- `POST /admin/user/update` with `target_user_id` plus any of `real_name`, `email`, `status`
- `POST /admin/user/assign-role` with `target_user_id`, `role`
- `POST /admin/user/revoke-role` with `target_user_id`, `role`
- `POST /admin/user/block` with `target_user_id`
- `POST /admin/user/soft-delete` with `target_user_id`
- `POST /admin/user/revoke-sessions` with `target_user_id`

All authenticated JSON `POST` endpoints (`/profile` and `/admin/*`) require CSRF protection via `csrf_token` body field or `X-CSRF-Token` header.

### Server-rendered HTML modules

- `GET /ui/register` and `POST /ui/register`
- `GET /ui/login` and `POST /ui/login`
- `GET /ui/verify-email` and `POST /ui/verify-email`
- `GET /ui/password-reset/request` and `POST /ui/password-reset/request`
- `GET /ui/password-reset/confirm` and `POST /ui/password-reset/confirm`
- `GET /ui/profile` and `POST /ui/profile` (authenticated)

All `POST /ui/*` requests require a valid `csrf_token` generated from the matching GET form.

Custom profile fields use key-value storage in `user_profile_fields` and are submitted as `profile[key]` (HTML) or `profile_fields[key]` (JSON).

Field acceptance/validation is controlled by a pluggable policy (`ProfileFieldPolicyInterface`).
The demo router uses `DatabaseProfileFieldPolicy` backed by `profile_field_definitions` and rejects unknown keys.

Host apps can define profile fields centrally with `ProfileFieldConfig` and set per-field user controls:
- `user_visible`: whether the field is shown in user-facing registration/profile views
- `user_editable`: whether the user can submit changes for that field
- `admin_visible`: whether the field is shown in admin user-profile read views
- `label`: display label for HTML modules

The policy enforces editability server-side, not only in the UI.

Runtime admin management is available (admin/super_admin only):
- JSON: `GET /admin/profile-fields`, `POST /admin/profile-fields/upsert`, `POST /admin/profile-fields/delete`
- HTML: `GET /ui/admin/profile-fields`, `POST /ui/admin/profile-fields/upsert`, `POST /ui/admin/profile-fields/delete`

Read-only admin user profile field views:
- JSON: `GET /admin/user/profile-fields?target_user_id=...`
- HTML: `GET /ui/admin/user/profile-fields?target_user_id=...`

Both views support `q`, `limit`, and `offset` for search and pagination.

These views only include fields with `admin_visible = true`.

Admin user list responses include quick links per user:
- `profile_fields_url`
- `profile_fields_ui_url`

Definitions are persisted in `profile_field_definitions`, and user-facing registration/profile forms reflect changes immediately.

All user-facing auth errors are generic to avoid account enumeration.

By default, `/password-reset/request` never returns reset tokens. For local debugging only, set `ModuleConfig::$exposeDebugTokens = true` to include `demo_token` in responses.

The demo emits an `X-Request-Id` response header and propagates that ID into audit entries and PSR-3 log context.

## Security regression tests

- `tests/security/request_context_test.php` validates request-id sanitization/allowlist behavior without database dependencies.
- `tests/security/php_mail_mailer_test.php` validates `PhpMailMailer` rejects invalid addresses and header-injection input.
- `tests/security/profile_field_policy_test.php` validates regex-safe matching behavior and absolute profile-field length limits.
- `tests/security/router_security_test.sh` validates:
	- authenticated JSON `POST /profile` is rejected without CSRF
	- authenticated JSON `POST /profile` succeeds with `X-CSRF-Token`
	- `POST /password-reset/request` does not expose `demo_token` by default
- `tests/run-security-tests.sh` is the runner used by `composer test:security`.
- The runner always executes request-id sanitization tests, and executes database-backed router tests when MariaDB/MySQL prerequisites are available.
- When MariaDB/MySQL or `pdo_mysql` is unavailable, database-backed router tests are skipped with an explicit message and the non-database security tests still run.
- Database-backed tests require a reachable MariaDB/MySQL configured via `NEXUS_DB_DSN`, `NEXUS_DB_USER`, `NEXUS_DB_PASS`.

### CI automation

- GitHub Actions workflow [`.github/workflows/security-tests.yml`](.github/workflows/security-tests.yml) runs `composer test:security` on pushes and pull requests to `main` with:
	- a non-database job for always-on fast security checks
	- a MariaDB-backed job so router integration security tests run without skip

## Phase-2 extension contracts already available

- Step-up orchestration: `StepUpServiceInterface` (with `NullStepUpService` default)
- TOTP hooks: `TotpServiceInterface`
- Passkey hooks: `PasskeyServiceInterface`
- OIDC hooks: `OidcProviderInterface`
- Recovery code hooks: `RecoveryCodeServiceInterface`
- Event hooks: `EventDispatcherInterface` (with `NullEventDispatcher` default)

Current auth flow emits event names: `user.registered`, `auth.login.succeeded`, `auth.login.denied_risk`, `auth.login.require_step_up`.

## Security defaults currently implemented

- PDO prepared statements
- `password_hash()` with Argon2id preferred
- Random token generation via `random_bytes()`
- Hashing of stored security tokens
- Session ID regeneration on login
- Secure security-header helper
- Rate-limit buckets for login and registration
- Audit events for registration and login outcomes
- RBAC role checks (`user`, `admin`, `super_admin`) with default permissions seed
- Super Admin protection for privileged role revocation/removal
- Pluggable risk engine with default outcomes: `allow`, `require_step_up`, `deny`
- Configurable session binding modes via `ModuleConfig::$ipBindingMode` (`off`, `strict`, `subnet`, `risk-based`)
- Optional user-agent binding via `ModuleConfig::$bindUserAgent`