<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\AdminUserServiceInterface;

final class AdminUserJsonController
{
    public function __construct(private readonly AdminUserServiceInterface $service)
    {
    }

    /**
     * @param array<string, mixed> $input
     * @return array{status: int, body: array<string, mixed>}
     */
    public function list(int $actorUserId, array $input): array
    {
        $query = (string) ($input['q'] ?? '');
        $limit = (int) ($input['limit'] ?? 50);
        $offset = (int) ($input['offset'] ?? 0);

        $result = $this->service->listUsers($actorUserId, $query, $limit, $offset);

        return ['status' => 200, 'body' => ['ok' => true] + $result];
    }

    /**
     * @param array<string, mixed> $input
     * @return array{status: int, body: array<string, mixed>}
     */
    public function update(int $actorUserId, int $targetUserId, array $input): array
    {
        $ok = $this->service->updateUser($actorUserId, $targetUserId, $input);

        return ['status' => $ok ? 200 : 400, 'body' => ['ok' => $ok]];
    }

    public function assignRole(int $actorUserId, int $targetUserId, string $role): array
    {
        $ok = $this->service->assignRole($actorUserId, $targetUserId, $role);

        return ['status' => $ok ? 200 : 400, 'body' => ['ok' => $ok]];
    }

    public function revokeRole(int $actorUserId, int $targetUserId, string $role): array
    {
        $ok = $this->service->revokeRole($actorUserId, $targetUserId, $role);

        return ['status' => $ok ? 200 : 400, 'body' => ['ok' => $ok]];
    }

    public function block(int $actorUserId, int $targetUserId): array
    {
        $ok = $this->service->blockUser($actorUserId, $targetUserId);

        return ['status' => $ok ? 200 : 400, 'body' => ['ok' => $ok]];
    }

    public function softDelete(int $actorUserId, int $targetUserId): array
    {
        $ok = $this->service->softDeleteUser($actorUserId, $targetUserId);

        return ['status' => $ok ? 200 : 400, 'body' => ['ok' => $ok]];
    }

    public function revokeSessions(int $actorUserId, int $targetUserId): array
    {
        $ok = $this->service->revokeUserSessions($actorUserId, $targetUserId);

        return ['status' => $ok ? 200 : 400, 'body' => ['ok' => $ok]];
    }
}
