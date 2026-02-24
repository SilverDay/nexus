<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Profile;

use Nexus\DropInUser\Contract\ProfileFieldPolicyInterface;

final class ConfigurableProfileFieldPolicy implements ProfileFieldPolicyInterface
{
    private const ABSOLUTE_MAX_FIELD_LENGTH = 4000;

    /**
    * @param array<string, array{required?: bool, max_length?: int, pattern?: string, user_visible?: bool, user_editable?: bool, admin_visible?: bool, label?: string}> $definitions
     */
    public function __construct(private readonly array $definitions)
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
        $visible = [];
        foreach ($fields as $key => $value) {
            if (!isset($this->definitions[$key])) {
                continue;
            }

            $definition = $this->definitions[$key];
            if (($definition['user_visible'] ?? true) !== true) {
                continue;
            }

            $visible[$key] = $value;
        }

        return $visible;
    }

    public function userFieldDefinitions(): array
    {
        $result = [];
        foreach ($this->definitions as $key => $definition) {
            if (($definition['user_visible'] ?? true) !== true) {
                continue;
            }

            $result[$key] = [
                'label' => isset($definition['label']) && is_string($definition['label']) && $definition['label'] !== ''
                    ? $definition['label']
                    : $key,
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
        $errors = [];
        $sanitized = [];

        foreach ($fields as $key => $value) {
            if (!is_string($key) || !is_string($value)) {
                continue;
            }

            if (!array_key_exists($key, $this->definitions)) {
                $errors[] = 'Unknown profile field: ' . $key;
                continue;
            }

            $definition = $this->definitions[$key];
            if (($definition['user_editable'] ?? true) !== true) {
                $errors[] = 'Field not editable by user: ' . $key;
                continue;
            }

            $trimmed = trim($value);

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
            foreach ($this->definitions as $key => $definition) {
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
