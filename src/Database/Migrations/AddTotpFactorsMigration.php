<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database\Migrations;

use Nexus\DropInUser\Database\MigrationInterface;
use PDO;

final class AddTotpFactorsMigration implements MigrationInterface
{
    public function version(): string
    {
        return '2026_02_24_000005';
    }

    public function description(): string
    {
        return 'Add TOTP factor storage for phase-2 MFA enrollment and verification';
    }

    public function up(PDO $pdo): void
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS user_totp_factors (
                user_id BIGINT UNSIGNED PRIMARY KEY,
                secret_enc TEXT NOT NULL,
                pending_expires_at DATETIME NULL,
                confirmed_at DATETIME NULL,
                last_used_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                CONSTRAINT fk_user_totp_factors_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                KEY idx_user_totp_factors_confirmed_at (confirmed_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
    }
}
