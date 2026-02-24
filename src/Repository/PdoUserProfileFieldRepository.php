<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Repository;

use Nexus\DropInUser\Contract\UserProfileFieldRepositoryInterface;
use PDO;

final class PdoUserProfileFieldRepository implements UserProfileFieldRepositoryInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function getFields(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT field_key, field_value
             FROM user_profile_fields
             WHERE user_id = :user_id
             ORDER BY field_key ASC'
        );
        $stmt->execute(['user_id' => $userId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $fields = [];
        foreach ($rows ?: [] as $row) {
            if (!is_array($row) || !isset($row['field_key'], $row['field_value'])) {
                continue;
            }
            $fields[(string) $row['field_key']] = (string) $row['field_value'];
        }

        return $fields;
    }

    public function upsertFields(int $userId, array $fields): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO user_profile_fields (user_id, field_key, field_value)
             VALUES (:user_id, :field_key, :field_value)
             ON DUPLICATE KEY UPDATE field_value = VALUES(field_value), updated_at = CURRENT_TIMESTAMP'
        );

        foreach ($fields as $fieldKey => $fieldValue) {
            $sanitizedKey = $this->sanitizeKey($fieldKey);
            $sanitizedValue = $this->sanitizeValue($fieldValue);

            if ($sanitizedKey === null || $sanitizedValue === null) {
                continue;
            }

            $stmt->execute([
                'user_id' => $userId,
                'field_key' => $sanitizedKey,
                'field_value' => $sanitizedValue,
            ]);
        }
    }

    public function deleteField(int $userId, string $fieldKey): void
    {
        $sanitizedKey = $this->sanitizeKey($fieldKey);
        if ($sanitizedKey === null) {
            return;
        }

        $stmt = $this->pdo->prepare(
            'DELETE FROM user_profile_fields
             WHERE user_id = :user_id AND field_key = :field_key'
        );
        $stmt->execute([
            'user_id' => $userId,
            'field_key' => $sanitizedKey,
        ]);
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

    private function sanitizeValue(string $fieldValue): ?string
    {
        $normalized = trim($fieldValue);
        if ($normalized === '') {
            return null;
        }

        return mb_substr($normalized, 0, 2000);
    }
}
