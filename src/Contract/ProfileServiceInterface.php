<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface ProfileServiceInterface
{
    /**
    * @return array{user: array<string, mixed>, profile_fields: array<string, string>, profile_field_definitions: array<string, array{label: string, editable: bool, required: bool}>}
     */
    public function getProfile(int $userId): array;

    /**
     * @param array<string, mixed> $profileFields
     */
    public function updateProfile(int $userId, string $realName, array $profileFields): bool;
}
