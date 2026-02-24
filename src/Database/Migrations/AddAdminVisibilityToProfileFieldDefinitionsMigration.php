<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database\Migrations;

use Nexus\DropInUser\Database\MigrationInterface;
use PDO;

final class AddAdminVisibilityToProfileFieldDefinitionsMigration implements MigrationInterface
{
    public function version(): string
    {
        return '2026_02_24_000004';
    }

    public function description(): string
    {
        return 'Add admin visibility flag for profile field definitions';
    }

    public function up(PDO $pdo): void
    {
        $existsStmt = $pdo->query(
            "SELECT COUNT(*)
             FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'profile_field_definitions'
               AND COLUMN_NAME = 'admin_visible'"
        );
        $exists = (int) $existsStmt->fetchColumn() > 0;

        if (!$exists) {
            $pdo->exec(
                'ALTER TABLE profile_field_definitions
                 ADD COLUMN admin_visible TINYINT(1) NOT NULL DEFAULT 1
                 AFTER user_editable'
            );
        }
    }
}
