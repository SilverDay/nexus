<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\ProfileFieldPolicyInterface;
use Nexus\DropInUser\Contract\ProfileServiceInterface;
use Nexus\DropInUser\Contract\UserProfileFieldRepositoryInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;

final class ProfileService implements ProfileServiceInterface
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly UserProfileFieldRepositoryInterface $profileFields,
        private readonly ProfileFieldPolicyInterface $profileFieldPolicy,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
    ) {
    }

    public function getProfile(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, username, email, real_name, status, email_verified_at
             FROM users
             WHERE id = :id AND deleted_at IS NULL
             LIMIT 1'
        );
        $stmt->execute(['id' => $userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!is_array($user)) {
            return ['user' => [], 'profile_fields' => []];
        }

        return [
            'user' => $user,
            'profile_fields' => $this->profileFieldPolicy->filterVisibleForUser($this->profileFields->getFields($userId)),
            'profile_field_definitions' => $this->profileFieldPolicy->userFieldDefinitions(),
        ];
    }

    public function updateProfile(int $userId, string $realName, array $profileFields): bool
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users
             SET real_name = :real_name, updated_at = CURRENT_TIMESTAMP
             WHERE id = :id AND deleted_at IS NULL'
        );
        $ok = $stmt->execute([
            'real_name' => trim($realName),
            'id' => $userId,
        ]);

        if (!$ok) {
            return false;
        }

        $normalized = [];
        foreach ($profileFields as $key => $value) {
            if (!is_string($key) || !is_scalar($value)) {
                continue;
            }
            $normalized[$key] = (string) $value;
        }

        $validated = $this->profileFieldPolicy->validateForProfileUpdate($normalized);
        if (!$validated['ok']) {
            return false;
        }

        $this->profileFields->upsertFields($userId, $validated['fields']);

        $context = $this->requestContext->asAuditContext();
        $context['updated_profile_keys'] = array_keys($validated['fields']);
        $this->auditLogger->log('user.profile.updated', $userId, $userId, $context);

        return true;
    }
}
