<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface UserProfileFieldRepositoryInterface
{
    /**
     * @return array<string, string>
     */
    public function getFields(int $userId): array;

    /**
     * @param array<string, string> $fields
     */
    public function upsertFields(int $userId, array $fields): void;

    public function deleteField(int $userId, string $fieldKey): void;
}
