<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database\Migrations;

use Nexus\DropInUser\Database\MigrationInterface;
use PDO;

final class AddUserProfileFieldsMigration implements MigrationInterface
{
    public function version(): string
    {
        return '2026_02_24_000002';
    }

    public function description(): string
    {
        return 'Add user profile fields key-value storage table';
    }

    public function up(PDO $pdo): void
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS user_profile_fields (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT UNSIGNED NOT NULL,
                field_key VARCHAR(100) NOT NULL,
                field_value TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_profile_field (user_id, field_key),
                KEY idx_user_profile_fields_user_id (user_id),
                CONSTRAINT fk_user_profile_fields_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
    }
}
