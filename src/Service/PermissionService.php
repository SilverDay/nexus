<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\PermissionServiceInterface;
use Nexus\DropInUser\Contract\RoleRepositoryInterface;

final class PermissionService implements PermissionServiceInterface
{
    public function __construct(private readonly RoleRepositoryInterface $roles)
    {
    }

    public function can(int $userId, string $permission): bool
    {
        return $this->roles->can($userId, $permission);
    }

    public function hasRole(int $userId, string $role): bool
    {
        return $this->roles->hasRole($userId, $role);
    }

    public function requirePermission(int $userId, string $permission): void
    {
        if (!$this->can($userId, $permission)) {
            throw new \RuntimeException('Forbidden');
        }
    }
}
