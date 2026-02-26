<?php

declare(strict_types=1);

/*
 * Configuration file for examples/module_webapp.php
 *
 * Edit this file to configure the demo application.
 * The most important settings are db_dsn, db_user, and db_password.
 */

return [
    'pdo' => null,

    'db_dsn' => 'mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4',
    'db_user' => 'root',
    'db_password' => '',

    'from_email' => 'noreply@example.com',
    'from_name' => 'Nexus Demo App',

    'email_token_ttl_seconds' => 3600,
    'password_reset_token_ttl_seconds' => 1800,
    'secure_cookies' => true,
    'same_site' => 'Lax',
    'ip_binding_mode' => 'subnet',
    'bind_user_agent' => true,
    'expose_debug_tokens' => false,

    'totp_key' => '',
    'google_oidc_client_id' => '',
    'google_oidc_client_secret' => '',
    'google_oidc_redirect_uri' => '',
    'passkey_webauthn_enabled' => false,

    'mail_transport' => 'null',
    'smtp_host' => '',
    'smtp_port' => 587,
    'smtp_username' => '',
    'smtp_password' => '',
    'smtp_encryption' => 'tls',
    'smtp_timeout_seconds' => 10,

    'email_template_locale' => 'en',
    'email_template_roots' => [
        __DIR__ . '/../../templates/email',
    ],
    'verification_link_template' => '',
    'admin_registration_notify_to' => '',

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
    ],
];
