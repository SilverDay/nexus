<?php

declare(strict_types=1);

use PDO;

/*
 * Optional drop-in config file for the demo router and migration runner.
 *
 * Set NEXUS_CONFIG_FILE to this file path (or your own):
 *   export NEXUS_CONFIG_FILE=/workspaces/nexus/examples/config/module.config.php
 *
 * To share the host application's PDO connection, return it as `pdo`.
 */

$sharedPdo = null;

/*
 * Example host-app PDO reuse (uncomment and adapt):
 *
 * $sharedPdo = new PDO(
 *     'mysql:host=127.0.0.1;port=3306;dbname=host_app;charset=utf8mb4',
 *     'host_user',
 *     'host_password',
 *     [
 *         PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
 *         PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
 *         PDO::ATTR_EMULATE_PREPARES => false,
 *     ]
 * );
 */

return [
    'pdo' => $sharedPdo,

    'db_dsn' => getenv('NEXUS_DB_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4',
    'db_user' => getenv('NEXUS_DB_USER') ?: 'root',
    'db_password' => getenv('NEXUS_DB_PASS') ?: '',

    'from_email' => 'noreply@example.com',
    'from_name' => 'Nexus User Module',

    'email_token_ttl_seconds' => 3600,
    'password_reset_token_ttl_seconds' => 1800,
    'secure_cookies' => true,
    'same_site' => 'Lax',
    'ip_binding_mode' => 'subnet',
    'bind_user_agent' => true,
    'expose_debug_tokens' => false,

    'totp_key' => getenv('NEXUS_TOTP_KEY') ?: '',
    'google_oidc_client_id' => getenv('NEXUS_GOOGLE_OIDC_CLIENT_ID') ?: '',
    'google_oidc_client_secret' => getenv('NEXUS_GOOGLE_OIDC_CLIENT_SECRET') ?: '',
    'google_oidc_redirect_uri' => getenv('NEXUS_GOOGLE_OIDC_REDIRECT_URI') ?: '',
    'passkey_webauthn_enabled' => getenv('NEXUS_PASSKEY_WEBAUTHN_ENABLED') ?: false,

    'mail_transport' => getenv('NEXUS_MAIL_TRANSPORT') ?: 'null',
    'smtp_host' => getenv('NEXUS_SMTP_HOST') ?: '',
    'smtp_port' => (int) (getenv('NEXUS_SMTP_PORT') ?: 587),
    'smtp_username' => getenv('NEXUS_SMTP_USERNAME') ?: '',
    'smtp_password' => getenv('NEXUS_SMTP_PASSWORD') ?: '',
    'smtp_encryption' => getenv('NEXUS_SMTP_ENCRYPTION') ?: 'tls',
    'smtp_timeout_seconds' => (int) (getenv('NEXUS_SMTP_TIMEOUT_SECONDS') ?: 10),

    'email_template_locale' => getenv('NEXUS_EMAIL_TEMPLATE_LOCALE') ?: 'en',
    'email_template_roots' => [
        __DIR__ . '/../../templates/email',
    ],
    // Optional absolute URL template, for example: https://app.example.com/verify-email?token={{token}}
    'verification_link_template' => getenv('NEXUS_VERIFICATION_LINK_TEMPLATE') ?: '',
    // Optional. Array or comma-separated string of admin recipients.
    'admin_registration_notify_to' => getenv('NEXUS_ADMIN_REGISTRATION_NOTIFY_TO') ?: '',

    // Optional array fallback when no matching .subject.txt/.body.txt template files exist.
    'email_templates' => [
        'verify_email' => [
            'subject' => 'Verify your email address',
            'text' => "Hello {{real_name}},\n\nUse this token to verify your email: {{token}}\n\nIf you did not sign up, you can ignore this message.",
        ],
    ],

    'profile_fields' => [
        'department' => [
            'label' => 'Department',
            'required' => false,
            'max_length' => 120,
            'user_visible' => true,
            'user_editable' => true,
        ],
        'timezone' => [
            'label' => 'Timezone',
            'required' => false,
            'max_length' => 120,
            'pattern' => '/^[A-Za-z_\/+\-]{2,120}$/',
            'user_visible' => true,
            'user_editable' => true,
        ],
    ],
];
