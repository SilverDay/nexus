<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Profile;

use Nexus\DropInUser\Contract\ProfileFieldPolicyInterface;

final class AllowAllProfileFieldPolicy implements ProfileFieldPolicyInterface
{
    public function validateForRegistration(array $fields): array
    {
        return ['ok' => true, 'fields' => $fields, 'errors' => []];
    }

    public function validateForProfileUpdate(array $fields): array
    {
        return ['ok' => true, 'fields' => $fields, 'errors' => []];
    }

    public function filterVisibleForUser(array $fields): array
    {
        return $fields;
    }

    public function userFieldDefinitions(): array
    {
        return [];
    }
}
