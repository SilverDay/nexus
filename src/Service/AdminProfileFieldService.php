<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AdminProfileFieldServiceInterface;
use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\ProfileFieldDefinitionRepositoryInterface;
use Nexus\DropInUser\Contract\RoleRepositoryInterface;
use Nexus\DropInUser\Contract\UserProfileFieldRepositoryInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;

final class AdminProfileFieldService implements AdminProfileFieldServiceInterface
{
    public function __construct(
        private readonly RoleRepositoryInterface $roles,
        private readonly ProfileFieldDefinitionRepositoryInterface $definitions,
        private readonly UserProfileFieldRepositoryInterface $userProfileFields,
        private readonly PDO $pdo,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
    ) {
    }

    public function listDefinitions(int $actorUserId): array
    {
        $this->assertAdmin($actorUserId);

        return $this->definitions->allDefinitions();
    }

    public function upsertDefinition(int $actorUserId, string $fieldKey, array $definition): bool
    {
        $this->assertAdmin($actorUserId);

        $pattern = isset($definition['pattern']) ? trim((string) $definition['pattern']) : null;
        if ($pattern !== null && $pattern !== '' && !$this->isSafeRegexPattern($pattern)) {
            return false;
        }

        $this->definitions->upsertDefinition($fieldKey, [
            'label' => (string) ($definition['label'] ?? $fieldKey),
            'required' => ($definition['required'] ?? false) ? true : false,
            'max_length' => isset($definition['max_length']) ? (int) $definition['max_length'] : null,
            'pattern' => $pattern,
            'user_visible' => ($definition['user_visible'] ?? true) ? true : false,
            'user_editable' => ($definition['user_editable'] ?? true) ? true : false,
            'admin_visible' => ($definition['admin_visible'] ?? true) ? true : false,
        ]);

        $context = $this->requestContext->asAuditContext();
        $context['field_key'] = $fieldKey;
        $this->auditLogger->log('admin.profile_field.upserted', $actorUserId, null, $context);

        return true;
    }

    public function deleteDefinition(int $actorUserId, string $fieldKey): bool
    {
        $this->assertAdmin($actorUserId);

        $this->definitions->deleteDefinition($fieldKey);

        $context = $this->requestContext->asAuditContext();
        $context['field_key'] = $fieldKey;
        $this->auditLogger->log('admin.profile_field.deleted', $actorUserId, null, $context);

        return true;
    }

    public function viewUserProfileFields(int $actorUserId, int $targetUserId, string $query = '', int $limit = 50, int $offset = 0): array
    {
        $this->assertAdmin($actorUserId);

        $safeQuery = trim($query);
        $safeLimit = max(1, min($limit, 200));
        $safeOffset = max(0, $offset);

        $userStmt = $this->pdo->prepare(
            'SELECT id, username, email, real_name, status
             FROM users
             WHERE id = :id AND deleted_at IS NULL
             LIMIT 1'
        );
        $userStmt->execute(['id' => $targetUserId]);
        $user = $userStmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($user)) {
            return ['user' => [], 'profile_fields' => []];
        }

        $allFields = $this->userProfileFields->getFields($targetUserId);
        $definitions = $this->definitions->allDefinitions();

        $visible = [];
        foreach ($allFields as $fieldKey => $value) {
            if (!isset($definitions[$fieldKey])) {
                continue;
            }

            if (($definitions[$fieldKey]['admin_visible'] ?? true) !== true) {
                continue;
            }

            if ($safeQuery !== '') {
                $label = (string) ($definitions[$fieldKey]['label'] ?? $fieldKey);
                $haystack = mb_strtolower($fieldKey . ' ' . $label . ' ' . $value);
                if (!str_contains($haystack, mb_strtolower($safeQuery))) {
                    continue;
                }
            }

            $visible[] = [
                'field_key' => $fieldKey,
                'label' => (string) ($definitions[$fieldKey]['label'] ?? $fieldKey),
                'value' => $value,
            ];
        }

        usort(
            $visible,
            static fn (array $a, array $b): int => strcmp((string) ($a['field_key'] ?? ''), (string) ($b['field_key'] ?? ''))
        );

        $total = count($visible);
        $paged = array_slice($visible, $safeOffset, $safeLimit);

        return [
            'user' => $user,
            'profile_fields' => array_values($paged),
            'total' => $total,
            'query' => $safeQuery,
            'limit' => $safeLimit,
            'offset' => $safeOffset,
        ];
    }

    private function assertAdmin(int $actorUserId): void
    {
        if (!$this->roles->hasRole($actorUserId, 'admin') && !$this->roles->hasRole($actorUserId, 'super_admin')) {
            throw new \RuntimeException('Forbidden');
        }
    }

    private function isSafeRegexPattern(string $pattern): bool
    {
        if (mb_strlen($pattern) > 255) {
            return false;
        }

        $dangerousFragments = ['(?R', '(?0', '(?&', '(?P>', '\\g{', '\\1', '\\2', '\\3'];
        foreach ($dangerousFragments as $fragment) {
            if (str_contains($pattern, $fragment)) {
                return false;
            }
        }

        if (preg_match('/\([^)]*[+*][^)]*\)[+*{]/', $pattern) === 1) {
            return false;
        }

        set_error_handler(static fn (): bool => true);
        try {
            return preg_match($pattern, 'probe') !== false;
        } finally {
            restore_error_handler();
        }
    }
}
