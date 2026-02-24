<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface AdminProfileFieldServiceInterface
{
    /**
     * @return array<string, array{label: string, required: bool, max_length?: int, pattern?: string, user_visible: bool, user_editable: bool}>
     */
    public function listDefinitions(int $actorUserId): array;

    /**
     * @param array<string, mixed> $definition
     */
    public function upsertDefinition(int $actorUserId, string $fieldKey, array $definition): bool;

    public function deleteDefinition(int $actorUserId, string $fieldKey): bool;

    /**
     * @return array{user: array<string, mixed>, profile_fields: list<array{field_key: string, label: string, value: string}>, total: int, query: string, limit: int, offset: int}
     */
    public function viewUserProfileFields(int $actorUserId, int $targetUserId, string $query = '', int $limit = 50, int $offset = 0): array;
}
