<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Profile;

use Nexus\DropInUser\Contract\ProfileFieldDefinitionRepositoryInterface;
use Nexus\DropInUser\Contract\ProfileFieldPolicyInterface;

final class DatabaseProfileFieldPolicy implements ProfileFieldPolicyInterface
{
    private const ABSOLUTE_MAX_FIELD_LENGTH = 4000;

    public function __construct(private readonly ProfileFieldDefinitionRepositoryInterface $definitions)
    {
    }

    public function validateForRegistration(array $fields): array
    {
        return $this->validate($fields, true);
    }

    public function validateForProfileUpdate(array $fields): array
    {
        return $this->validate($fields, false);
    }

    public function filterVisibleForUser(array $fields): array
    {
        $defs = $this->definitions->allDefinitions();
        $visible = [];
        foreach ($fields as $key => $value) {
            if (!isset($defs[$key])) {
                continue;
            }

            if (($defs[$key]['user_visible'] ?? true) !== true) {
                continue;
            }

            $visible[$key] = $value;
        }

        return $visible;
    }

    public function userFieldDefinitions(): array
    {
        $defs = $this->definitions->allDefinitions();
        $result = [];

        foreach ($defs as $key => $definition) {
            if (($definition['user_visible'] ?? true) !== true) {
                continue;
            }

            $result[$key] = [
                'label' => isset($definition['label']) && is_string($definition['label']) ? $definition['label'] : $key,
                'editable' => ($definition['user_editable'] ?? true) === true,
                'required' => ($definition['required'] ?? false) === true,
            ];
        }

        return $result;
    }

    /**
     * @param array<string, string> $fields
     * @return array{ok: bool, fields: array<string, string>, errors: list<string>}
     */
    private function validate(array $fields, bool $enforceRequired): array
    {
        $defs = $this->definitions->allDefinitions();
        $errors = [];
        $sanitized = [];

        foreach ($fields as $key => $value) {
            if (!isset($defs[$key])) {
                $errors[] = 'Unknown profile field: ' . $key;
                continue;
            }

            $definition = $defs[$key];
            if (($definition['user_editable'] ?? true) !== true) {
                $errors[] = 'Field not editable by user: ' . $key;
                continue;
            }

            $trimmed = trim((string) $value);
            if ($trimmed === '') {
                continue;
            }

            $maxLength = self::ABSOLUTE_MAX_FIELD_LENGTH;
            if (isset($definition['max_length']) && is_int($definition['max_length'])) {
                $maxLength = max(1, min($definition['max_length'], self::ABSOLUTE_MAX_FIELD_LENGTH));
            }

            if (mb_strlen($trimmed) > $maxLength) {
                $errors[] = 'Field too long: ' . $key;
                continue;
            }

            if (isset($definition['pattern']) && is_string($definition['pattern']) && $definition['pattern'] !== '' && !$this->matchesPattern($definition['pattern'], $trimmed)) {
                $errors[] = 'Invalid format: ' . $key;
                continue;
            }

            $sanitized[$key] = $trimmed;
        }

        if ($enforceRequired) {
            foreach ($defs as $key => $definition) {
                if (($definition['user_editable'] ?? true) !== true) {
                    continue;
                }

                if (($definition['required'] ?? false) === true && (!isset($sanitized[$key]) || $sanitized[$key] === '')) {
                    $errors[] = 'Required field missing: ' . $key;
                }
            }
        }

        return [
            'ok' => $errors === [],
            'fields' => $sanitized,
            'errors' => $errors,
        ];
    }

    private function matchesPattern(string $pattern, string $value): bool
    {
        set_error_handler(static fn (): bool => true);
        try {
            return preg_match($pattern, $value) === 1;
        } finally {
            restore_error_handler();
        }
    }
}
