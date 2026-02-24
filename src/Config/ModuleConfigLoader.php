<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Config;

use PDO;
use RuntimeException;

/**
 * Loads module bootstrap settings from an optional PHP config file with
 * environment-variable fallback.
 *
 * Supported config file keys (all optional):
 * - db_dsn, db_user, db_password
 * - from_email, from_name
 * - email_token_ttl_seconds, password_reset_token_ttl_seconds
 * - secure_cookies, same_site
 * - ip_binding_mode, bind_user_agent, expose_debug_tokens
 * - pdo (PDO instance from host app for shared DB usage)
 * - profile_fields (array definitions for ProfileFieldConfig)
 * - totp_key, google_oidc_client_id, google_oidc_client_secret,
 *   google_oidc_redirect_uri, passkey_webauthn_enabled
 * - mail_transport, smtp_*, email_template_locale, email_template_roots,
 *   verification_link_template, admin_registration_notify_to, email_templates
 *   (optional fallback array templates)
 */
final class ModuleConfigLoader
{
    /**
     * @return array{
     *     config: ModuleConfig,
     *     pdo: ?PDO,
     *     settings: array<string,mixed>,
     *     profile_fields: array<string,mixed>
     * }
     */
    public static function load(?string $configFilePath = null): array
    {
        $settings = self::loadSettings($configFilePath);

        $config = new ModuleConfig(
            dbDsn: self::stringValue($settings, 'db_dsn', getenv('NEXUS_DB_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4'),
            dbUser: self::stringValue($settings, 'db_user', getenv('NEXUS_DB_USER') ?: 'root'),
            dbPassword: self::stringValue($settings, 'db_password', getenv('NEXUS_DB_PASS') ?: ''),
            fromEmail: self::stringValue($settings, 'from_email', 'noreply@example.com'),
            fromName: self::stringValue($settings, 'from_name', 'Nexus User Module'),
            emailTokenTtlSeconds: self::intValue($settings, 'email_token_ttl_seconds', 3600),
            passwordResetTokenTtlSeconds: self::intValue($settings, 'password_reset_token_ttl_seconds', 1800),
            secureCookies: self::boolValue($settings, 'secure_cookies', true),
            sameSite: self::stringValue($settings, 'same_site', 'Lax'),
            ipBindingMode: self::stringValue($settings, 'ip_binding_mode', 'subnet'),
            bindUserAgent: self::boolValue($settings, 'bind_user_agent', true),
            exposeDebugTokens: self::boolValue($settings, 'expose_debug_tokens', false),
        );

        $pdo = $settings['pdo'] ?? null;
        if ($pdo !== null && !$pdo instanceof PDO) {
            throw new RuntimeException('Invalid config: "pdo" must be a PDO instance when provided.');
        }

        $profileFields = $settings['profile_fields'] ?? [];
        if (!is_array($profileFields)) {
            $profileFields = [];
        }

        return [
            'config' => $config,
            'pdo' => $pdo,
            'settings' => $settings,
            'profile_fields' => $profileFields,
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private static function loadSettings(?string $configFilePath): array
    {
        if ($configFilePath === null || trim($configFilePath) === '') {
            return [];
        }

        $path = trim($configFilePath);
        if (!is_file($path)) {
            throw new RuntimeException('Config file not found: ' . $path);
        }

        $loaded = require $path;
        if (!is_array($loaded)) {
            throw new RuntimeException('Config file must return an array: ' . $path);
        }

        return $loaded;
    }

    /**
     * @param array<string,mixed> $settings
     */
    private static function stringValue(array $settings, string $key, string $default): string
    {
        if (!array_key_exists($key, $settings)) {
            return $default;
        }

        return trim((string) $settings[$key]);
    }

    /**
     * @param array<string,mixed> $settings
     */
    private static function intValue(array $settings, string $key, int $default): int
    {
        if (!array_key_exists($key, $settings)) {
            return $default;
        }

        return max(0, (int) $settings[$key]);
    }

    /**
     * @param array<string,mixed> $settings
     */
    private static function boolValue(array $settings, string $key, bool $default): bool
    {
        if (!array_key_exists($key, $settings)) {
            return $default;
        }

        $value = $settings[$key];
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value !== 0;
        }

        $normalized = strtolower(trim((string) $value));
        if ($normalized === '') {
            return false;
        }

        return in_array($normalized, ['1', 'true', 'yes', 'on'], true);
    }
}
