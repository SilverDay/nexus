<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;

final class PasskeyCredentialService
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
    ) {
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function listForUser(int $userId): array
    {
        if ($userId <= 0) {
            return [];
        }

        $stmt = $this->pdo->prepare(
            'SELECT credential_id, credential_label, created_at, last_used_at
             FROM user_passkey_credentials
             WHERE user_id = :user_id
             ORDER BY created_at DESC'
        );
        $stmt->execute(['user_id' => $userId]);

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (!is_array($rows)) {
            return [];
        }

        $credentials = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $credentials[] = [
                'credential_id' => (string) ($row['credential_id'] ?? ''),
                'label' => (string) ($row['credential_label'] ?? ''),
                'created_at' => (string) ($row['created_at'] ?? ''),
                'last_used_at' => isset($row['last_used_at']) ? (string) $row['last_used_at'] : null,
            ];
        }

        return $credentials;
    }

    public function revokeForUser(int $userId, string $credentialId): bool
    {
        if ($userId <= 0 || trim($credentialId) === '') {
            return false;
        }

        $stmt = $this->pdo->prepare(
            'DELETE FROM user_passkey_credentials
             WHERE user_id = :user_id AND credential_id = :credential_id'
        );
        $stmt->execute([
            'user_id' => $userId,
            'credential_id' => trim($credentialId),
        ]);

        $revoked = $stmt->rowCount() > 0;
        if ($revoked) {
            $context = $this->requestContext->asAuditContext();
            $this->auditLogger->log('auth.passkey.revoked', $userId, $userId, $context);
        }

        return $revoked;
    }
}
