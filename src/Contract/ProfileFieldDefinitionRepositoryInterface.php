<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface ProfileFieldDefinitionRepositoryInterface
{
    /**
    * @return array<string, array{required?: bool, max_length?: int, pattern?: string, user_visible?: bool, user_editable?: bool, admin_visible?: bool, label?: string}>
     */
    public function allDefinitions(): array;

    /**
    * @param array{required?: bool, max_length?: int, pattern?: string, user_visible?: bool, user_editable?: bool, admin_visible?: bool, label?: string} $definition
     */
    public function upsertDefinition(string $fieldKey, array $definition): void;

    public function deleteDefinition(string $fieldKey): void;
}
