<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface AdminUserServiceInterface
{
    /**
     * @return array{items: list<array<string, mixed>>, total: int}
     */
    public function listUsers(int $actorUserId, string $query = '', int $limit = 50, int $offset = 0): array;

    /**
     * @param array<string, mixed> $changes
     */
    public function updateUser(int $actorUserId, int $targetUserId, array $changes): bool;

    public function assignRole(int $actorUserId, int $targetUserId, string $role): bool;

    public function revokeRole(int $actorUserId, int $targetUserId, string $role): bool;

    public function blockUser(int $actorUserId, int $targetUserId): bool;

    public function softDeleteUser(int $actorUserId, int $targetUserId): bool;

    public function revokeUserSessions(int $actorUserId, int $targetUserId): bool;
}
