<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface ProfileFieldPolicyInterface
{
    /**
     * @param array<string, string> $fields
     * @return array{ok: bool, fields: array<string, string>, errors: list<string>}
     */
    public function validateForRegistration(array $fields): array;

    /**
     * @param array<string, string> $fields
     * @return array{ok: bool, fields: array<string, string>, errors: list<string>}
     */
    public function validateForProfileUpdate(array $fields): array;

    /**
     * @param array<string, string> $fields
     * @return array<string, string>
     */
    public function filterVisibleForUser(array $fields): array;

    /**
     * @return array<string, array{label: string, editable: bool, required: bool}>
     */
    public function userFieldDefinitions(): array;
}
