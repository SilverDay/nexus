<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface RoleRepositoryInterface
{
    public function hasRole(int $userId, string $roleName): bool;

    public function can(int $userId, string $permission): bool;

    public function assignRole(int $userId, string $roleName): bool;

    public function revokeRole(int $userId, string $roleName): bool;

    /**
     * @return list<string>
     */
    public function rolesForUser(int $userId): array;
}
