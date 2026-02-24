<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database\Migrations;

use Nexus\DropInUser\Database\MigrationInterface;
use PDO;

final class AddPasskeyCredentialsMigration implements MigrationInterface
{
    public function version(): string
    {
        return '2026_02_24_000008';
    }

    public function description(): string
    {
        return 'Add passkey credential storage for WebAuthn phase-2';
    }

    public function up(PDO $pdo): void
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS user_passkey_credentials (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT UNSIGNED NOT NULL,
                credential_id VARCHAR(255) NOT NULL,
                public_key TEXT NOT NULL,
                sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
                transports VARCHAR(255) NULL,
                aaguid CHAR(36) NULL,
                credential_label VARCHAR(120) NULL,
                last_used_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_passkey_credential_id (credential_id),
                KEY idx_passkey_user_id (user_id),
                CONSTRAINT fk_passkey_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
    }
}
