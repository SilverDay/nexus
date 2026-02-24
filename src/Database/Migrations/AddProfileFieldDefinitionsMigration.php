<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database\Migrations;

use Nexus\DropInUser\Database\MigrationInterface;
use PDO;

final class AddProfileFieldDefinitionsMigration implements MigrationInterface
{
    public function version(): string
    {
        return '2026_02_24_000003';
    }

    public function description(): string
    {
        return 'Add profile field definitions table for runtime field policy management';
    }

    public function up(PDO $pdo): void
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS profile_field_definitions (
                field_key VARCHAR(100) PRIMARY KEY,
                label VARCHAR(120) NOT NULL,
                is_required TINYINT(1) NOT NULL DEFAULT 0,
                max_length INT UNSIGNED NULL,
                pattern VARCHAR(255) NULL,
                user_visible TINYINT(1) NOT NULL DEFAULT 1,
                user_editable TINYINT(1) NOT NULL DEFAULT 1,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
    }
}
