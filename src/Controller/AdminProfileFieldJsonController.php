<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\AdminProfileFieldServiceInterface;

final class AdminProfileFieldJsonController
{
    public function __construct(private readonly AdminProfileFieldServiceInterface $service)
    {
    }

    public function list(int $actorUserId): array
    {
        return [
            'status' => 200,
            'body' => [
                'ok' => true,
                'definitions' => $this->service->listDefinitions($actorUserId),
            ],
        ];
    }

    /**
     * @param array<string, mixed> $input
     */
    public function upsert(int $actorUserId, array $input): array
    {
        $fieldKey = (string) ($input['field_key'] ?? '');
        $ok = $this->service->upsertDefinition($actorUserId, $fieldKey, $input);

        return ['status' => $ok ? 200 : 400, 'body' => ['ok' => $ok]];
    }

    public function delete(int $actorUserId, string $fieldKey): array
    {
        $ok = $this->service->deleteDefinition($actorUserId, $fieldKey);

        return ['status' => $ok ? 200 : 400, 'body' => ['ok' => $ok]];
    }

    /**
     * @param array<string, mixed> $input
     */
    public function viewUserProfile(int $actorUserId, int $targetUserId, array $input = []): array
    {
        $query = (string) ($input['q'] ?? '');
        $limit = (int) ($input['limit'] ?? 50);
        $offset = (int) ($input['offset'] ?? 0);

        return [
            'status' => 200,
            'body' => ['ok' => true] + $this->service->viewUserProfileFields($actorUserId, $targetUserId, $query, $limit, $offset),
        ];
    }
}
