# Copilot Instructions — Drop-In User Management Module

## Project Mission

This repository implements a **security-first, framework-agnostic PHP 8.2+ drop-in user management module** for MariaDB/MySQL.

The module must be:

* Secure by default (OWASP aligned)
* Production-grade
* Fully object-oriented
* Easily embeddable into different PHP applications
* Extensible without modifying core code
* PS-15 compliant where applicable

This is **NOT** a framework and **NOT** a Keycloak-style IAM.
Keep the design lightweight, modular, and developer-friendly.

---

## Core Architectural Principles

Copilot MUST follow these principles when generating code:

### 1. Security First

All code must assume hostile environments.

Mandatory practices:

* Use prepared statements (PDO only)
* Never expose whether a user exists (no enumeration)
* Use `password_hash()` (Argon2id preferred)
* Use `random_bytes()` for all tokens
* Hash sensitive tokens at rest
* Regenerate session ID on login
* Enforce CSRF protection on state-changing operations
* Escape all output in templates
* Apply secure cookie flags
* Implement rate limiting hooks
* Log security-relevant events

If unsure, choose the **more secure default**.

---

### 2. Framework Agnostic

The module must:

* NOT depend on Laravel, Symfony, etc.
* NOT ship a full router
* Provide handler/controller classes that can be mounted anywhere
* Include only a tiny demo router for examples
* Use plain PHP templates by default
* Support both HTML and JSON (headless) modes

---

### 3. Object-Oriented & Extensible

Design for long-term maintainability.

Requirements:

* PSR-4 autoloading
* Strict types everywhere
* Dependency injection preferred
* Use interfaces for replaceable components
* Avoid static state except where clearly justified
* Favor composition over inheritance
* Provide clear extension points (hooks/events)

Core services must be swappable.

---

### 4. Database Requirements

* MariaDB/MySQL via PDO
* UTF8MB4 everywhere
* Proper indexes and constraints
* Idempotent migrations
* Schema version table
* Soft delete preferred
* Minimal PII storage

Username and email must both be unique.

---

### 5. Authentication Requirements

Phase 1 (must be fully implemented):

* Registration (username, email, realname)
* Email verification
* Login via username OR email
* Secure session handling
* Remember-me (selector + hashed validator)
* Password reset
* Password change
* Role-based access control
* Admin user management
* Audit logging

Architecture must already support Phase 2:

* TOTP MFA
* WebAuthn passkeys
* Google OIDC login
* Recovery codes
* Step-up authentication

---

### 6. Session & Device Security

Implement:

* Session ID regeneration on login
* Configurable IP binding modes:

  * off
  * strict
  * subnet
  * risk-based
* Optional user-agent binding
* Concurrent session tracking
* Session revocation
* Trusted device support hooks

Never hard-bind IP in a way that breaks mobile users.

---

### 7. Authorization Model

Baseline roles:

* Super Admin
* Admin
* User

Must support:

* Custom roles
* Permission checks (`can()`)
* Role checks
* Super Admin protection rules
* Admin audit trail

---

### 8. Audit Logging (Mandatory)

Audit log must capture:

* login success/failure
* password reset events
* email changes
* role changes
* admin actions
* session revocations
* security-sensitive events

Each entry should include when available:

* actor user id
* target user id
* timestamp
* source IP
* user agent hash
* correlation/request id

Audit logs must never contain secrets.

---

### 9. Risk Engine (Lightweight)

Provide a pluggable `RiskEngineInterface`.

Default implementation should detect:

* new device
* suspicious IP change

Risk output:

* allow
* require_step_up
* deny (optional)

Do NOT integrate external reputation services by default.

---

### 10. Email & Template System

Must support:

* Overridable templates
* Locale-aware lookup with fallback
* Strict escaping
* Pluggable mail transport:

  * SMTP
  * PHP mail()
* No heavy template engines

Templates must be WCAG-friendly.

---

### 11. Embeddable UI Modules

Provide modules for:

* register
* login
* verify email
* reset password
* change password
* profile
* sessions/devices
* admin user management

Each module must support:

* server-rendered HTML
* JSON API mode

No inline CSS. Provide clean CSS hooks.

---

### 12. Rate Limiting & Anti-Abuse

Implement pluggable rate limiter.

Must support:

* per IP
* per identifier (username/email)
* progressive delays or cooldowns

User-facing responses must remain generic.

---

### 13. Security Headers Helper

Provide helper to emit recommended headers:

* CSP (configurable template)
* X-Content-Type-Options
* Referrer-Policy
* frame-ancestors
* Permissions-Policy

Must be safe and configurable.

---

### 14. Admin Break-Glass (Disabled by Default)

Provide an emergency recovery mechanism that:

* is OFF by default
* requires explicit config enablement
* requires multi-step confirmation
* uses a one-time external secret
* generates audit events
* has minimal recovery scope

Document clearly that this is sensitive.

---

## Coding Standards

Copilot must generate code that is:

* PHP 8.2+
* `declare(strict_types=1);`
* PSR-12 style
* Typed properties and return types
* Small, focused classes
* Meaningful exceptions
* No dead code
* No debug leftovers
* No hardcoded secrets

Prefer clarity over cleverness.

---

## Logging & Observability

* Support PSR-3 `LoggerInterface`
* Include correlation/request IDs
* Provide structured context arrays
* Never log passwords or tokens
* Provide security-event logging hooks

---

## Accessibility Requirements

HTML templates must:

* use proper labels
* support keyboard navigation
* include ARIA where appropriate
* provide error summaries
* maintain focus after validation errors

---

## Definition of Done (Quality Gate)

Generated code should allow verification that:

* No user enumeration occurs
* CSRF protection works
* Rate limiting triggers correctly
* Remember-me tokens rotate safely
* Sessions regenerate on login
* Audit log entries are written
* Templates are overrideable
* i18n fallback works
* Security headers emit correctly
* Break-glass is disabled unless enabled

---

## When in Doubt

If a design choice is unclear:

1. Prefer the **more secure** option.
2. Prefer the **more extensible** option.
3. Avoid adding heavy dependencies.
4. Keep the module drop-in friendly.
5. Document assumptions in code comments.

Security, clarity, and maintainability take priority over convenience.
