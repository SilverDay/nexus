<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database\Migrations;

use Nexus\DropInUser\Database\MigrationInterface;
use PDO;

final class AddPasskeyChallengesMigration implements MigrationInterface
{
    public function version(): string
    {
        return '2026_02_24_000009';
    }

    public function description(): string
    {
        return 'Add passkey challenge storage for registration and authentication ceremonies';
    }

    public function up(PDO $pdo): void
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS passkey_challenges (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                challenge_hash CHAR(64) NOT NULL,
                user_id BIGINT UNSIGNED NULL,
                purpose VARCHAR(20) NOT NULL,
                expires_at DATETIME NOT NULL,
                consumed_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_passkey_challenge_hash (challenge_hash),
                KEY idx_passkey_challenges_user_id (user_id),
                KEY idx_passkey_challenges_expires_at (expires_at),
                CONSTRAINT fk_passkey_challenges_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
    }
}
