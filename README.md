# Nexus Drop-In User Module

[![Security Tests](https://github.com/SilverDay/nexus/actions/workflows/security-tests.yml/badge.svg)](https://github.com/SilverDay/nexus/actions/workflows/security-tests.yml)

Security-first, framework-agnostic PHP 8.2+ user management module for MariaDB/MySQL.

## What this is

A **drop-in auth/user module** you can mount into an existing PHP app.

- Not a full framework
- Not a standalone IAM server
- Built for embedding and extension

## What you get

- Registration + email verification
- Login (username or email) + secure sessions + remember-me
- Password reset + password change
- Role checks (`user`, `admin`, `super_admin`) with permission checks (`can()`)
- TOTP + recovery codes + step-up verification
- Passkeys (WebAuthn) with safe default disabled mode
- Google OIDC login hooks
- Session/device listing and revocation
- Audit logging for security-sensitive actions
- HTML modules and JSON endpoints

## Quick start

1. Install dependencies:

```bash
composer install
```

2. Configure database (environment mode):

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

## Configuration modes

The module now supports **both** environment-based and file-based configuration.

### A) Environment variables

Used by default when no config file is provided.

Primary keys:

- `NEXUS_DB_DSN`
- `NEXUS_DB_USER`
- `NEXUS_DB_PASS`
- `NEXUS_TOTP_KEY`
- `NEXUS_GOOGLE_OIDC_CLIENT_ID`
- `NEXUS_GOOGLE_OIDC_CLIENT_SECRET`
- `NEXUS_GOOGLE_OIDC_REDIRECT_URI`
- `NEXUS_PASSKEY_WEBAUTHN_ENABLED`

### B) Config file (`NEXUS_CONFIG_FILE`)

Point `NEXUS_CONFIG_FILE` to a PHP file returning an array.

```bash
export NEXUS_CONFIG_FILE=/workspaces/nexus/examples/config/module.config.php
```

See the template in `examples/config/module.config.php`.

Supported config keys include:

- Core config: `db_dsn`, `db_user`, `db_password`, `from_email`, `from_name`
- Security behavior: `secure_cookies`, `same_site`, `ip_binding_mode`, `bind_user_agent`
- Phase-2 toggles/secrets: `totp_key`, `google_oidc_*`, `passkey_webauthn_enabled`
- Mail transport: `mail_transport`, `smtp_host`, `smtp_port`, `smtp_username`, `smtp_password`, `smtp_encryption`, `smtp_timeout_seconds`
- Mail template files: `email_template_locale`, `email_template_roots`, `verification_link_template`, `admin_registration_notify_to`
- Optional mail fallback templates: `email_templates`
- UI fields: `profile_fields`

### Email text and transport configuration

You can configure both **what is sent** and **how it is sent** from the config file.

Transport options:

- `mail_transport = null` (default; no mail sent)
- `mail_transport = php` (uses PHP `mail()`)
- `mail_transport = smtp` (uses SMTP with optional AUTH/STARTTLS)

Example transport config:

```php
'mail_transport' => 'smtp',
'smtp_host' => 'smtp.example.com',
'smtp_port' => 587,
'smtp_username' => 'smtp-user',
'smtp_password' => 'smtp-password',
'smtp_encryption' => 'tls', // tls|ssl|none
'smtp_timeout_seconds' => 10,
'verification_link_template' => 'https://app.example.com/verify-email?token={{token}}',
'admin_registration_notify_to' => 'security@example.com,ops@example.com',
```

Email text is file-based by default. Template file lookup is:

- `<root>/<locale>/<template_name>.subject.txt`
- `<root>/<locale>/<template_name>.body.txt`
- fallback to language-only locale (for example `de` from `de-DE`)
- fallback to `en`

Example file-template config:

```php
'email_template_locale' => 'de-DE',
'email_template_roots' => [
	__DIR__ . '/../../templates/email',
	'/opt/myapp/mail-templates',
],
```

Default template example:

- `templates/email/en/verify_email.subject.txt`
- `templates/email/en/verify_email.body.txt`

Default mail notification templates shipped:

- `verify_email`
- `password_reset_requested`
- `password_reset_completed`
- `admin_new_user_registered`

Template file contents are preformatted text with placeholders:

```text
Please verify your account
```

```text
Hi {{real_name}},

Your verification token: {{token}}
```

Optional array fallback when no file template exists:

```php
'email_templates' => [
	'verify_email' => [
		'subject' => 'Please verify your account',
		'text' => "Hi {{real_name}},\n\nYour verification token: {{token}}",
	],
],
```

Available placeholders for `verify_email`:

- `{{token}}`
- `{{verify_link}}`
- `{{username}}`
- `{{email}}`
- `{{real_name}}`

Available placeholders for `admin_new_user_registered`:

- `{{user_id}}`
- `{{username}}`
- `{{email}}`
- `{{real_name}}`
- `{{source_ip}}`
- `{{request_id}}`

When `admin_registration_notify_to` is set (array or comma-separated list), admin notifications are emitted on successful registration using the `admin_new_user_registered` template.

### Host app database reuse (drop-in embedding)

For host-app embedding, the config file can provide a **shared PDO instance** via `pdo`.

If `pdo` is present, the demo router and migration runner reuse it instead of opening a separate DB connection.

This lets the module use the same database/session context as the embedding application.

### Host app bootstrap example

For a concrete shared-PDO integration example, see:

- `examples/host_app_bootstrap.php`

Run it like this:

```bash
php -S 127.0.0.1:8090 examples/host_app_bootstrap.php
```

It exposes sample host-mounted routes:

- `POST /host/auth/register`
- `POST /host/auth/login`

## Example endpoints (JSON)

- `POST /register`
- `POST /login`
- `POST /verify-email`
- `POST /password-reset/request`
- `POST /password-reset/confirm`
- `POST /totp/enroll/begin` (auth + CSRF)
- `POST /totp/enroll/confirm` (auth + CSRF)
- `POST /recovery-codes/regenerate` (auth + CSRF)
- `POST /step-up/verify`
- `POST /passkeys/register/begin` (auth + CSRF)
- `POST /passkeys/register/finish` (auth + CSRF)
- `POST /passkeys/authenticate/begin` (CSRF)
- `POST /passkeys/authenticate/finish` (CSRF)
- `GET /passkeys/list` (auth)
- `POST /passkeys/revoke` (auth + CSRF)
- `GET /sessions` (auth)
- `POST /sessions/revoke` (auth + CSRF)
- `GET /oidc/google/start`
- `GET /oidc/google/callback`

## HTML modules

- Register/login/verify-email/password-reset
- TOTP enroll + recovery code regeneration
- Step-up verification
- Passkey list + revoke
- Sessions/devices list + revoke
- Profile

All `POST /ui/*` routes require valid CSRF tokens.

## Testing

Fast security suite:

```bash
composer test:security
```

Full DB-backed security suite (ephemeral MariaDB):

```bash
composer test:security:db
```

Focused WebAuthn-enabled DB path:

```bash
composer test:security:db:webauthn
```

## Security defaults

- PDO prepared statements
- Argon2id password hashing (preferred)
- `random_bytes()` token generation
- Hashed tokens at rest
- Session ID regeneration on login
- CSRF enforcement on state-changing routes
- Generic auth failures (no account enumeration)
- Audit events for critical auth/security actions
- Pluggable risk engine with `allow`, `require_step_up`, `deny`

## Architecture notes

Key extension interfaces:

- `StepUpServiceInterface`
- `TotpServiceInterface`
- `RecoveryCodeServiceInterface`
- `PasskeyServiceInterface`
- `PasskeyCeremonyValidatorInterface`
- `OidcProviderInterface`
- `EventDispatcherInterface`

Primary composition roots:

- `examples/minimal_router.php`
- `migrations/run.php`

## Current status

Phase-1 and planned Phase-2 capabilities are implemented in this repository, with DB-backed security regression coverage and CI workflow validation.
