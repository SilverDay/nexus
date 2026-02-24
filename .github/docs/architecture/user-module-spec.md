You are a senior PHP security engineer and library author. Design and implement a drop-in, framework-agnostic PHP 8.2+ user management module for MariaDB/MySQL (PDO). It must be embeddable into different PHP sites with minimal integration.

DECISIONS / CONSTRAINTS
- DB: MariaDB/MySQL only (for now), via PDO prepared statements.
- Sessions: PHP native sessions are acceptable and preferred over JWT for web use.
- Routing: DO NOT build a full routing framework. Provide controller/handler classes that can be mounted into an existing router/framework. Provide a tiny optional reference router only as an integration example.
- UI: Support BOTH (a) server-rendered embeddable forms/modules and (b) headless JSON API mode for SPA/JS clients.
- Tenancy: single-tenant only.
- Mail: support configuration for SMTP (host, port, auth, TLS) and PHP native mail(). Provide MailerInterface with pluggable transports.
- Identity: username and email must both be unique. Login must accept either username OR email.

CORE FEATURES (MUST IMPLEMENT)
1) Registration
- Fields: username, email, realname (+ pluggable custom profile fields)
- Configurable validation rules/policies
- Anti-abuse: rate limiting + optional CAPTCHA hook

2) Email verification
- On registration and on email change
- Token-based, expiration, single-use
- Email change grace period option

3) Password management
- Reset request -> email -> set new password, secure token lifecycle
- Change password with current password, optional “recent auth” requirement
- Hashing: password_hash() with Argon2id preferred, policy checks configurable

4) Authentication methods (phase 1 minimal + phase 2 roadmap)
Phase 1 (deliver working code now):
- Password login
- Session hardening
- “Remember me” via selector+validator tokens (validator hashed at rest)
- Provide interfaces/stubs for MFA/TOTP/Passkeys/OIDC so architecture supports them cleanly
Phase 2 (roadmap + extension points in code now):
- TOTP MFA (enroll/verify, QR)
- Passkeys (WebAuthn)
- Google Login (OpenID Connect / OAuth2)
- Recovery / fallback codes
- Step-up authentication API

5) Secure login & session management
- Session fixation protection: regenerate ID on login
- Secure cookie flags, strict mode guidance
- Bind session to client properties configurable:
  * IP binding modes: off / strict / subnet / risk-based
  * user-agent hash binding optional
- Concurrent session management: list/revoke sessions

6) Role management & authorization
- Built-in baseline roles: Super Admin, Admin, User
- Support custom roles and permissions stored in DB (RBAC)
- Authorization API: can($user, $permission), hasRole(), requirePermission()
- Super Admin safeguards: cannot be removed/demoted/deleted by non-superadmin

7) User administration (admin UI + API)
- List/search users, view details
- Edit, block/disable, soft delete (default), optional hard delete
- Assign roles, revoke sessions, reset auth methods (audited)

8) Audit log (REQUIRED)
- Record security events + admin actions:
  login success/fail, password reset requested/completed, email change, role changes, user block/delete, session revoke, etc.
- Include actor, target, timestamp, source IP, UA hash, correlation/request id
- Provide retention configuration and redaction/PII minimization options

9) Risk-based hooks (keep simple)
- Provide RiskEngineInterface / hook system. Implement basic default:
  * new device detection (based on device cookie / session)
  * suspicious IP change (configurable thresholds)
- Risk engine outputs: allow / require step-up / deny (deny optional)
- No external reputation services by default; provide integration hook.

10) Email templates + i18n-ready rendering
- Template system for user/admin notifications
- Support overriding templates per host app
- Design for localization: template lookup by locale (e.g., en, de), with fallback
- Implement a small renderer with strict escaping (no template injection)

11) Embeddable forms/modules + headless API
- Provide self-service modules: register, login, verify email, reset password, change password, profile, sessions/devices
- Provide admin modules: user list/detail, role mgmt
- Each module usable as:
  a) server-rendered HTML (templateable, CSS hooks, no inline styling)
  b) JSON endpoints returning structured errors and data

12) Pluggable user profile fields
- Allow adding custom fields without forking core:
  * custom validators
  * custom storage mapping (KV table or JSON column; justify choice)
  * extend registration/profile forms

13) Security header helpers
- Provide helper to emit recommended headers for module pages:
  CSP (template), frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, etc.
- Must be configurable and non-breaking.

SECURITY REQUIREMENTS (MUST ADDRESS EXPLICITLY)
- Prevent user enumeration across login/reset/verify
- CSRF protection for all state-changing forms (HTML mode)
- XSS-safe rendering with strict escaping strategy
- Rate limiting: per IP + per identifier (username/email)
- Token security: random_bytes, hashed tokens at rest, expiry, single-use
- Logging: security events without leaking secrets
- Privacy: minimal PII, retention config, soft delete with optional PII redaction
- Secure defaults for session cookies: Secure, HttpOnly, SameSite
- Input validation + output encoding strategy documented
- Reset/remember-me flows resistant to theft/replay

ADDITIONAL QUALITY / OPERABILITY REQUIREMENTS (MUST IMPLEMENT)
A) Accessibility
- Templates must be WCAG-friendly: associated labels, ARIA attributes where needed, error summary, keyboard navigation, focus management guidance.

B) Brute-force / credential stuffing
- Add throttling per IP + identifier, progressive delays, safe lockouts/cooldowns.
- User-facing responses must not reveal whether an account exists.

C) Migration safety
- Provide schema version table and idempotent migration scripts.
- Include safe indexes and constraints; document expected MySQL settings (e.g., utf8mb4, collation).

D) Operational hooks
- Support PSR-3 logger (LoggerInterface) and correlation/request IDs across logs + audit entries.
- Provide structured logging option (context arrays).

E) Admin break-glass (disabled by default)
- Provide a secure, auditable emergency recovery procedure for Super Admin:
  * must be explicitly enabled via config
  * requires multi-step confirmation and a one-time token/secret stored outside DB (or injected at runtime)
  * produces audit events
  * minimal scope (restore access, rotate credentials, revoke sessions)
  * clear documentation and warnings

ARCHITECTURE OUTPUT (DELIVERABLES)
1) High-level architecture description + textual class diagram
2) Public APIs and interfaces:
   - AuthService, UserService, UserRepository, RoleRepository, PermissionService
   - TokenService, EmailVerificationService, PasswordResetService
   - SessionManager, RememberMeService, DeviceService
   - AuditLogger, RiskEngine
   - MailerInterface + transports
   - Renderer/View + TemplateLoader + I18nResolver
   - CsrfService, RateLimiter, SecurityHeaders
3) Package folder structure (Composer, PSR-4 namespace Vendor\DropInUser)
4) DB schema (tables + indexes + constraints) for default installation + migrations
5) Implement a minimal but complete “first working version” in code:
   - Registration + email verification
   - Login (username/email) + session hardening + remember-me
   - Password reset + password change
   - Roles (baseline + custom) and authorization checks
   - Admin user list/edit/block/soft-delete + assign roles
   - Audit log capturing all above events
   - Basic HTML templates + JSON API mode
   - Security header helper + PSR-3 logging integration
6) Integration example:
   - bootstrap config + DB + session init
   - example mounting of handlers in a simple demo router (for demo only)
   - example embedding server-rendered modules into PHP pages
   - example using JSON API endpoints
7) Security checklist + threat model summary
8) Extension points:
   - events/hooks for custom profile fields, mail templates, risk engine, external IAM, custom password policies

DEFINITION OF DONE (VERIFY)
- Provide a short “acceptance test checklist” (manual + automated) that verifies:
  * no enumeration in auth/reset flows
  * CSRF works
  * rate limiting works
  * audit log populated correctly
  * remember-me tokens rotate and are invalidated properly
  * admin role safeguards enforced
  * templates are overrideable + i18n fallback works
  * headers helper emits expected headers
  * break-glass feature is disabled unless explicitly enabled

OUTPUT FORMAT
Proceed step-by-step:
1) Provide the architecture & class diagram (text) + DB schema + folder structure.
2) Implement the first working version with code blocks (organized by file path).
3) Provide an integration walkthrough + security checklist + acceptance tests.
4) Provide a phase-2 plan for: full TOTP, WebAuthn passkeys, Google OIDC, recovery codes UI, advanced risk engine.

---

## Implementation status matrix (as of 2026-02-24)

Legend:
- Implemented: available and wired in current code
- Partial: foundation exists, but one or more required sub-features are pending
- Planned: not yet implemented (or interface-only roadmap)

| Area | Status | Notes |
|---|---|---|
| Registration (username/email/realname/custom fields) | Implemented | Includes policy-based custom profile fields and rate limiting hooks. |
| Email verification | Partial | Token lifecycle implemented; email-change verification + grace-period workflow still pending. |
| Password reset | Implemented | Secure token request/consume lifecycle with generic responses and token hashing at rest. |
| Password change (current password / recent auth) | Planned | Not exposed as a dedicated flow yet. |
| Password login + remember-me | Implemented | Username/email login, session regeneration, selector+validator remember-me rotation. |
| Phase-2 auth interfaces (TOTP/Passkeys/OIDC/recovery/step-up) | Partial | Contracts/stubs present; full providers and UX are pending. |
| Secure session management | Implemented | IP binding modes, optional UA binding, concurrent session tracking and revocation. |
| RBAC baseline + checks | Partial | Baseline roles, role assignment/revocation and permission wiring exist; full custom role lifecycle UI/API is pending. |
| Admin user management | Partial | List/search/update/block/soft-delete/revoke-sessions implemented; hard-delete option is pending. |
| Audit logging | Partial | Security/admin events with actor/target/request context are implemented; retention/redaction policy controls are pending. |
| Risk engine hooks | Implemented | Basic risk outcomes (`allow`, `require_step_up`, `deny`) and pluggable interface are available. |
| Template system + locale fallback | Implemented | Overrideable templates with locale fallback (`en` default) and escaping renderer. |
| Embeddable HTML + JSON modules | Partial | Core auth/profile/admin modules exist; sessions/devices self-service and change-password module are pending. |
| Pluggable profile fields | Implemented | KV storage + runtime field definitions + user/admin visibility/editability controls. |
| Security headers helper | Implemented | Configurable CSP/referrer/frame/permissions/content-type header helper included. |
| CSRF/XSS/Enumeration protections | Implemented | CSRF for UI and authenticated JSON writes, strict template escaping, generic auth-facing failures. |
| Break-glass admin recovery | Planned | Explicitly required by spec; not yet implemented in code. |
| Automated security regression tests | Partial | Non-DB tests + DB-backed router security tests in place; broader acceptance suite remains pending. |

### Implemented API surface (interface → implementation → usage)

#### Core auth/admin services

| Interface | Concrete class | Primary usage in demo integration |
|---|---|---|
| `AuthServiceInterface` | `Nexus\DropInUser\Service\AuthService` | JSON: `POST /register`, `POST /login`; HTML: `/ui/register`, `/ui/login` |
| `EmailVerificationServiceInterface` | `Nexus\DropInUser\Service\EmailVerificationService` | JSON/HTML verify flows: `POST /verify-email`, `POST /ui/verify-email` |
| `PasswordResetServiceInterface` | `Nexus\DropInUser\Service\PasswordResetService` | JSON/HTML reset flows: `POST /password-reset/request`, `POST /password-reset/confirm`, `POST /ui/password-reset/*` |
| `RememberMeServiceInterface` | `Nexus\DropInUser\Service\RememberMeService` | Login remember-me issuance and cookie-based consume/rotate in router bootstrap |
| `SessionManagerInterface` | `Nexus\DropInUser\Service\SessionManager` | Session validation/revocation checks and admin revoke actions |
| `ProfileServiceInterface` | `Nexus\DropInUser\Service\ProfileService` | JSON/HTML profile flows: `GET/POST /profile`, `GET/POST /ui/profile` |
| `AdminUserServiceInterface` | `Nexus\DropInUser\Service\AdminUserService` | Admin JSON endpoints: `/admin/users`, `/admin/user/*` |
| `AdminProfileFieldServiceInterface` | `Nexus\DropInUser\Service\AdminProfileFieldService` | Admin field definition + user field views: `/admin/profile-fields*`, `/admin/user/profile-fields` |
| `PermissionServiceInterface` | `Nexus\DropInUser\Service\PermissionService` | Internal authorization checks for admin/service operations |
| `RiskEngineInterface` | `Nexus\DropInUser\Risk\BasicRiskEngine` | Login risk decisioning (`allow` / `require_step_up` / `deny`) |
| `StepUpServiceInterface` | `Nexus\DropInUser\Service\NullStepUpService` | Step-up challenge hook when risk engine returns `require_step_up` |
| `EventDispatcherInterface` | `Nexus\DropInUser\Event\NullEventDispatcher` | Auth and security event dispatch hooks |

#### Persistence/security infrastructure

| Interface | Concrete class | Primary usage |
|---|---|---|
| `UserRepositoryInterface` | `Nexus\DropInUser\Repository\PdoUserRepository` | User registration, lookup, status/admin updates |
| `RoleRepositoryInterface` | `Nexus\DropInUser\Repository\PdoRoleRepository` | Role assignment/revocation/checks |
| `UserProfileFieldRepositoryInterface` | `Nexus\DropInUser\Repository\PdoUserProfileFieldRepository` | KV profile field persistence |
| `ProfileFieldDefinitionRepositoryInterface` | `Nexus\DropInUser\Repository\PdoProfileFieldDefinitionRepository` | Runtime field definition policy storage |
| `ProfileFieldPolicyInterface` | `Nexus\DropInUser\Profile\DatabaseProfileFieldPolicy` | Server-side profile field visibility/editability/validation |
| `AuditLoggerInterface` | `Nexus\DropInUser\Audit\PdoAuditLogger` | Security and admin event trail |
| `TokenServiceInterface` | `Nexus\DropInUser\Security\TokenService` | Token generation/hashing and UA hashing |
| `MailerInterface` | `Nexus\DropInUser\Mail\NullMailer` / `Nexus\DropInUser\Mail\PhpMailMailer` | Verification/reset notifications (transport swappable) |
| `TemplateRendererInterface` | `Nexus\DropInUser\View\PhpTemplateRenderer` | HTML module rendering with escaped templates |
| `SecurityHeadersInterface` | `Nexus\DropInUser\Security\SecurityHeaders` | Response security header emission |
| `RateLimiter` (contract in `src/RateLimit`) | `Nexus\DropInUser\RateLimit\PdoRateLimiter` | Registration/login throttling buckets |

#### Controllers and mounted routes (demo router)

| Controller | Backing service(s) | Mounted routes |
|---|---|---|
| `AuthJsonController` | `AuthServiceInterface` | `POST /register`, `POST /login` |
| direct service calls | `EmailVerificationServiceInterface`, `PasswordResetServiceInterface` | `POST /verify-email`, `POST /password-reset/request`, `POST /password-reset/confirm` |
| `ProfileJsonController` | `ProfileServiceInterface` | `GET /profile`, `POST /profile` |
| `AdminUserJsonController` | `AdminUserServiceInterface` | `GET /admin/users`, `POST /admin/user/update`, `POST /admin/user/assign-role`, `POST /admin/user/revoke-role`, `POST /admin/user/block`, `POST /admin/user/soft-delete`, `POST /admin/user/revoke-sessions` |
| `AdminProfileFieldJsonController` | `AdminProfileFieldServiceInterface` | `GET /admin/profile-fields`, `POST /admin/profile-fields/upsert`, `POST /admin/profile-fields/delete`, `GET /admin/user/profile-fields` |
| `AuthHtmlController` | `AuthServiceInterface`, `EmailVerificationServiceInterface`, `PasswordResetServiceInterface` | `GET/POST /ui/register`, `GET/POST /ui/login`, `GET/POST /ui/verify-email`, `GET/POST /ui/password-reset/request`, `GET/POST /ui/password-reset/confirm` |
| `ProfileHtmlController` | `ProfileServiceInterface` | `GET/POST /ui/profile` |
| `AdminProfileFieldHtmlController` | `AdminProfileFieldServiceInterface` | `GET /ui/admin/profile-fields`, `POST /ui/admin/profile-fields/upsert`, `POST /ui/admin/profile-fields/delete`, `GET /ui/admin/user/profile-fields` |

### Acceptance checklist (manual + automated)

| Requirement | Validation command / action | Expected result | Pass criteria |
|---|---|---|---|
| No enumeration in auth/reset flows | `composer test:security` (includes router security checks when DB is available) | Generic success/failure messaging for reset/auth paths; no account-existence leak | No test failures and no response variant that exposes account existence |
| CSRF protection works | `composer test:security` | `/profile` JSON write fails without CSRF and succeeds with `X-CSRF-Token` | Security suite reports CSRF checks passed |
| Rate limiting works | Manual: perform repeated `/login` attempts with wrong password from same IP/identifier | Requests eventually return generic denied response due to throttling | Throttle triggers without changing user-facing message specificity |
| Audit log populated for security/admin actions | Manual DB check after register/login/admin action: `SELECT event_type, actor_user_id, target_user_id, request_id FROM audit_logs ORDER BY id DESC LIMIT 10;` | Relevant events present with request context fields | Rows exist for tested actions and contain non-empty `event_type` + context |
| Remember-me rotation/invalidation works | Manual: login with remember-me, reuse old token after rotation or reset password | Old remember token is rejected; rotated/new token required | Prior token cannot restore session once rotated/revoked |
| Admin role safeguards enforced | Manual: try revoking/demoting `super_admin` with non-super-admin actor via `/admin/user/revoke-role` | Operation denied | Response indicates failure/forbidden and no DB role change occurs |
| Template override + locale fallback works | Manual: add override template path/locale variant and render; remove locale-specific template and rerender | Locale-specific template used when present, fallback to `en` otherwise | Render output switches to override and fallback behavior is consistent |
| Security headers helper emits expected headers | Manual: `curl -i http://127.0.0.1:8080/ui/login` | Response includes CSP, `X-Content-Type-Options`, `Referrer-Policy`, and frame restrictions | Required headers present and non-empty |
| Break-glass disabled unless enabled | Manual review: verify no active break-glass route/flow by default; run regression tests | No default break-glass execution path available | Feature remains inaccessible until explicitly implemented + enabled |

Notes:
- Database-backed checks require MariaDB/MySQL connectivity and `pdo_mysql`.
- In environments without database support, `composer test:security` still validates non-database security controls and reports database-backed checks as skipped.

### Threat model summary

#### Assets to protect

- User credentials (`password_hash`, reset/verification/remember-me token material)
- Session integrity (`PHPSESSID`, server-side session records, remember-me cookies)
- Authorization state (roles/permissions and admin controls)
- Security telemetry (audit logs, correlation/request IDs)
- Profile data (including custom profile-field values)

#### Likely attacker profiles

- Anonymous internet attacker performing brute-force/credential-stuffing and enumeration attempts
- Authenticated low-privilege user attempting privilege escalation or admin-function abuse
- Network/on-path attacker attempting token replay or session theft (primarily on misconfigured non-TLS deployments)
- Malicious automation probing CSRF/XSS/input-validation weaknesses

#### Primary trust boundaries

- Client browser ↔ host application HTTP boundary (cookies, headers, CSRF tokens)
- Host application ↔ module services/repositories boundary (validated input vs persistent state)
- Module ↔ database boundary (least-privilege DB access and prepared statements)
- Module ↔ email transport boundary (outbound notification channel integrity)

#### Top threats and current mitigations

| Threat | Mitigation currently implemented |
|---|---|
| Account enumeration | Generic auth/reset user-facing responses and audit-side detail separation |
| CSRF on state changes | CSRF token checks for HTML forms and authenticated JSON write paths |
| Credential stuffing / brute force | Per-IP and per-identifier rate-limiting hooks |
| Session fixation/replay | Session ID regeneration on login, remember-me selector/validator rotation, token hashing at rest |
| Stored/reflected XSS in templates | Escaping renderer and plain-PHP template discipline |
| Privilege escalation via admin endpoints | Role checks (`admin`/`super_admin`), super-admin safeguards, audited admin actions |
| Malicious regex/input abuse in profile fields | Pattern safety validation and bounded field-length checks |
| Header/log injection via request metadata | Request ID allowlist sanitization and bounded formatting |

#### Residual risks / planned hardening

- Break-glass recovery workflow is not implemented yet (planned, must remain disabled-by-default until shipped).
- Full password-change flow (current-password + recent-auth requirement) is pending.
- Audit retention/redaction policy controls require explicit implementation and operational defaults.
- Optional CAPTCHA integration hook is specified but not yet exposed in the demo flow.