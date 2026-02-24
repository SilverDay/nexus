<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Repository;

use Nexus\DropInUser\Contract\RoleRepositoryInterface;
use PDO;

final class PdoRoleRepository implements RoleRepositoryInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function hasRole(int $userId, string $roleName): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1
             FROM user_roles ur
             INNER JOIN roles r ON r.id = ur.role_id
             WHERE ur.user_id = :user_id AND r.name = :role_name
             LIMIT 1'
        );
        $stmt->execute([
            'user_id' => $userId,
            'role_name' => $roleName,
        ]);

        return (bool) $stmt->fetchColumn();
    }

    public function can(int $userId, string $permission): bool
    {
        if ($this->hasRole($userId, 'super_admin')) {
            return true;
        }

        $stmt = $this->pdo->prepare(
            'SELECT 1
             FROM user_roles ur
             INNER JOIN role_permissions rp ON rp.role_id = ur.role_id
             INNER JOIN permissions p ON p.id = rp.permission_id
             WHERE ur.user_id = :user_id AND p.name = :permission
             LIMIT 1'
        );
        $stmt->execute([
            'user_id' => $userId,
            'permission' => $permission,
        ]);

        return (bool) $stmt->fetchColumn();
    }

    public function assignRole(int $userId, string $roleName): bool
    {
        $roleId = $this->findRoleId($roleName);
        if ($roleId === null) {
            return false;
        }

        $stmt = $this->pdo->prepare(
            'INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (:user_id, :role_id)'
        );

        return $stmt->execute([
            'user_id' => $userId,
            'role_id' => $roleId,
        ]);
    }

    public function revokeRole(int $userId, string $roleName): bool
    {
        $roleId = $this->findRoleId($roleName);
        if ($roleId === null) {
            return false;
        }

        $stmt = $this->pdo->prepare(
            'DELETE FROM user_roles WHERE user_id = :user_id AND role_id = :role_id'
        );

        return $stmt->execute([
            'user_id' => $userId,
            'role_id' => $roleId,
        ]);
    }

    public function rolesForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT r.name
             FROM user_roles ur
             INNER JOIN roles r ON r.id = ur.role_id
             WHERE ur.user_id = :user_id
             ORDER BY r.name ASC'
        );
        $stmt->execute(['user_id' => $userId]);
        $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);

        return array_values(array_map(static fn (mixed $value): string => (string) $value, $rows ?: []));
    }

    private function findRoleId(string $roleName): ?int
    {
        $stmt = $this->pdo->prepare('SELECT id FROM roles WHERE name = :name LIMIT 1');
        $stmt->execute(['name' => $roleName]);
        $value = $stmt->fetchColumn();

        return $value === false ? null : (int) $value;
    }
}
