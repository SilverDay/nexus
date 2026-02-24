<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface PermissionServiceInterface
{
    public function can(int $userId, string $permission): bool;

    public function hasRole(int $userId, string $role): bool;

    public function requirePermission(int $userId, string $permission): void;
}
