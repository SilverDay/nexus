<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database\Migrations;

use Nexus\DropInUser\Database\MigrationInterface;
use PDO;

final class AddRecoveryCodesMigration implements MigrationInterface
{
    public function version(): string
    {
        return '2026_02_24_000006';
    }

    public function description(): string
    {
        return 'Add recovery code storage for MFA fallback';
    }

    public function up(PDO $pdo): void
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS user_recovery_codes (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT UNSIGNED NOT NULL,
                code_hash CHAR(64) NOT NULL,
                consumed_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_recovery_codes_hash (code_hash),
                KEY idx_user_recovery_codes_user_id (user_id),
                KEY idx_user_recovery_codes_consumed_at (consumed_at),
                CONSTRAINT fk_user_recovery_codes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
    }
}
