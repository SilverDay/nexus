<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Repository;

use Nexus\DropInUser\Contract\ProfileFieldDefinitionRepositoryInterface;
use PDO;

final class PdoProfileFieldDefinitionRepository implements ProfileFieldDefinitionRepositoryInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function allDefinitions(): array
    {
        $stmt = $this->pdo->query(
            'SELECT field_key, label, is_required, max_length, pattern, user_visible, user_editable, admin_visible
             FROM profile_field_definitions
             ORDER BY field_key ASC'
        );
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $definitions = [];
        foreach ($rows ?: [] as $row) {
            if (!is_array($row) || !isset($row['field_key'])) {
                continue;
            }

            $definitions[(string) $row['field_key']] = [
                'label' => (string) ($row['label'] ?? (string) $row['field_key']),
                'required' => (int) ($row['is_required'] ?? 0) === 1,
                'max_length' => isset($row['max_length']) ? (int) $row['max_length'] : null,
                'pattern' => isset($row['pattern']) && is_string($row['pattern']) && $row['pattern'] !== '' ? $row['pattern'] : null,
                'user_visible' => (int) ($row['user_visible'] ?? 1) === 1,
                'user_editable' => (int) ($row['user_editable'] ?? 1) === 1,
                'admin_visible' => (int) ($row['admin_visible'] ?? 1) === 1,
            ];
        }

        return $definitions;
    }

    public function upsertDefinition(string $fieldKey, array $definition): void
    {
        $sanitizedKey = $this->sanitizeKey($fieldKey);
        if ($sanitizedKey === null) {
            return;
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO profile_field_definitions (
                field_key,
                label,
                is_required,
                max_length,
                pattern,
                user_visible,
                user_editable,
                admin_visible
            ) VALUES (
                :field_key,
                :label,
                :is_required,
                :max_length,
                :pattern,
                :user_visible,
                :user_editable,
                :admin_visible
            ) ON DUPLICATE KEY UPDATE
                label = VALUES(label),
                is_required = VALUES(is_required),
                max_length = VALUES(max_length),
                pattern = VALUES(pattern),
                user_visible = VALUES(user_visible),
                user_editable = VALUES(user_editable),
                admin_visible = VALUES(admin_visible),
                updated_at = CURRENT_TIMESTAMP'
        );

        $stmt->execute([
            'field_key' => $sanitizedKey,
            'label' => $this->sanitizeLabel((string) ($definition['label'] ?? $sanitizedKey)),
            'is_required' => (($definition['required'] ?? false) === true) ? 1 : 0,
            'max_length' => isset($definition['max_length']) ? max(1, min((int) $definition['max_length'], 4000)) : null,
            'pattern' => $this->sanitizePattern(isset($definition['pattern']) && is_string($definition['pattern']) ? $definition['pattern'] : null),
            'user_visible' => (($definition['user_visible'] ?? true) === true) ? 1 : 0,
            'user_editable' => (($definition['user_editable'] ?? true) === true) ? 1 : 0,
            'admin_visible' => (($definition['admin_visible'] ?? true) === true) ? 1 : 0,
        ]);
    }

    public function deleteDefinition(string $fieldKey): void
    {
        $sanitizedKey = $this->sanitizeKey($fieldKey);
        if ($sanitizedKey === null) {
            return;
        }

        $stmt = $this->pdo->prepare('DELETE FROM profile_field_definitions WHERE field_key = :field_key');
        $stmt->execute(['field_key' => $sanitizedKey]);
    }

    private function sanitizeKey(string $fieldKey): ?string
    {
        $normalized = strtolower(trim($fieldKey));
        if ($normalized === '' || mb_strlen($normalized) > 100) {
            return null;
        }

        if (!preg_match('/^[a-z0-9_\.\-]+$/', $normalized)) {
            return null;
        }

        return $normalized;
    }

    private function sanitizeLabel(string $label): string
    {
        $normalized = trim($label);

        return $normalized === '' ? 'Field' : mb_substr($normalized, 0, 120);
    }

    private function sanitizePattern(?string $pattern): ?string
    {
        if (!is_string($pattern)) {
            return null;
        }

        $normalized = trim($pattern);
        if ($normalized === '') {
            return null;
        }

        $normalized = mb_substr($normalized, 0, 255);

        $dangerousFragments = ['(?R', '(?0', '(?&', '(?P>', '\\g{', '\\1', '\\2', '\\3'];
        foreach ($dangerousFragments as $fragment) {
            if (str_contains($normalized, $fragment)) {
                return null;
            }
        }

        if (preg_match('/\([^)]*[+*][^)]*\)[+*{]/', $normalized) === 1) {
            return null;
        }

        set_error_handler(static fn (): bool => true);
        try {
            if (preg_match($normalized, 'probe') === false) {
                return null;
            }
        } finally {
            restore_error_handler();
        }

        return $normalized;
    }
}
