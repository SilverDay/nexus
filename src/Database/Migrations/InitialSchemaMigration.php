<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database\Migrations;

use Nexus\DropInUser\Database\MigrationInterface;
use PDO;

final class InitialSchemaMigration implements MigrationInterface
{
    public function version(): string
    {
        return '2026_02_24_000001';
    }

    public function description(): string
    {
        return 'Initial user, auth, RBAC, sessions, and audit schema';
    }

    public function up(PDO $pdo): void
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS users (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                email VARCHAR(190) NOT NULL,
                real_name VARCHAR(120) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT "active",
                email_verified_at DATETIME NULL,
                last_login_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                deleted_at DATETIME NULL,
                UNIQUE KEY uniq_users_username (username),
                UNIQUE KEY uniq_users_email (email),
                KEY idx_users_status (status),
                KEY idx_users_deleted_at (deleted_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS roles (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(80) NOT NULL,
                is_system TINYINT(1) NOT NULL DEFAULT 0,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_roles_name (name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS permissions (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(120) NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_permissions_name (name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS user_roles (
                user_id BIGINT UNSIGNED NOT NULL,
                role_id BIGINT UNSIGNED NOT NULL,
                assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, role_id),
                CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS role_permissions (
                role_id BIGINT UNSIGNED NOT NULL,
                permission_id BIGINT UNSIGNED NOT NULL,
                PRIMARY KEY (role_id, permission_id),
                CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS email_verification_tokens (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT UNSIGNED NOT NULL,
                token_hash CHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                consumed_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_email_verification_token_hash (token_hash),
                KEY idx_email_verification_user_id (user_id),
                CONSTRAINT fk_email_verification_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT UNSIGNED NOT NULL,
                token_hash CHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                consumed_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_password_reset_token_hash (token_hash),
                KEY idx_password_reset_user_id (user_id),
                CONSTRAINT fk_password_reset_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS remember_me_tokens (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT UNSIGNED NOT NULL,
                selector CHAR(24) NOT NULL,
                validator_hash CHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                last_used_at DATETIME NULL,
                revoked_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_remember_me_selector (selector),
                KEY idx_remember_me_user_id (user_id),
                CONSTRAINT fk_remember_me_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS user_sessions (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT UNSIGNED NOT NULL,
                session_id VARCHAR(128) NOT NULL,
                ip_address VARCHAR(45) NULL,
                ua_hash CHAR(64) NULL,
                last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                revoked_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_sessions_session_id (session_id),
                KEY idx_user_sessions_user_id (user_id),
                CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS audit_logs (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                event_type VARCHAR(120) NOT NULL,
                actor_user_id BIGINT UNSIGNED NULL,
                target_user_id BIGINT UNSIGNED NULL,
                source_ip VARCHAR(45) NULL,
                user_agent_hash CHAR(64) NULL,
                request_id VARCHAR(120) NULL,
                context_json JSON NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                KEY idx_audit_logs_event_type (event_type),
                KEY idx_audit_logs_actor (actor_user_id),
                KEY idx_audit_logs_target (target_user_id),
                KEY idx_audit_logs_created_at (created_at),
                CONSTRAINT fk_audit_logs_actor FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
                CONSTRAINT fk_audit_logs_target FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS rate_limit_hits (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                bucket VARCHAR(255) NOT NULL,
                created_at DATETIME NOT NULL,
                KEY idx_rate_limit_hits_bucket_created (bucket, created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );

        $this->seedDefaultRoles($pdo);
        $this->seedDefaultPermissions($pdo);
    }

    private function seedDefaultRoles(PDO $pdo): void
    {
        $stmt = $pdo->prepare('INSERT IGNORE INTO roles (name, is_system) VALUES (:name, 1)');
        foreach (['super_admin', 'admin', 'user'] as $role) {
            $stmt->execute(['name' => $role]);
        }
    }

    private function seedDefaultPermissions(PDO $pdo): void
    {
        $permissions = [
            'user.manage',
            'role.assign',
            'session.revoke',
        ];

        $insertPermission = $pdo->prepare('INSERT IGNORE INTO permissions (name) VALUES (:name)');
        foreach ($permissions as $permission) {
            $insertPermission->execute(['name' => $permission]);
        }

        $assign = $pdo->prepare(
            'INSERT IGNORE INTO role_permissions (role_id, permission_id)
             SELECT r.id, p.id
             FROM roles r, permissions p
             WHERE r.name = :role_name AND p.name = :permission_name'
        );

        foreach (['admin', 'super_admin'] as $role) {
            foreach ($permissions as $permission) {
                $assign->execute([
                    'role_name' => $role,
                    'permission_name' => $permission,
                ]);
            }
        }
    }
}
