<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;

final class SessionDeviceService
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
    public function listForUser(int $userId, string $currentSessionId = ''): array
    {
        if ($userId <= 0) {
            return [];
        }

        $stmt = $this->pdo->prepare(
            'SELECT session_id, ip_address, last_seen_at, created_at
             FROM user_sessions
             WHERE user_id = :user_id AND revoked_at IS NULL
             ORDER BY last_seen_at DESC, created_at DESC'
        );
        $stmt->execute(['user_id' => $userId]);

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (!is_array($rows)) {
            return [];
        }

        $sessions = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $sessionId = (string) ($row['session_id'] ?? '');
            if ($sessionId === '') {
                continue;
            }

            $sessions[] = [
                'session_id' => $sessionId,
                'session_hint' => $this->sessionHint($sessionId),
                'ip_address' => (string) ($row['ip_address'] ?? ''),
                'last_seen_at' => (string) ($row['last_seen_at'] ?? ''),
                'created_at' => (string) ($row['created_at'] ?? ''),
                'is_current' => $currentSessionId !== '' && hash_equals($currentSessionId, $sessionId),
            ];
        }

        return $sessions;
    }

    public function revokeForUser(int $userId, string $sessionId): bool
    {
        if ($userId <= 0 || trim($sessionId) === '') {
            return false;
        }

        $stmt = $this->pdo->prepare(
            'UPDATE user_sessions
             SET revoked_at = UTC_TIMESTAMP()
             WHERE user_id = :user_id AND session_id = :session_id AND revoked_at IS NULL'
        );
        $stmt->execute([
            'user_id' => $userId,
            'session_id' => trim($sessionId),
        ]);

        $revoked = $stmt->rowCount() > 0;
        if ($revoked) {
            $context = $this->requestContext->asAuditContext();
            $this->auditLogger->log('auth.session.revoked', $userId, $userId, $context);
        }

        return $revoked;
    }

    private function sessionHint(string $sessionId): string
    {
        $trimmed = trim($sessionId);
        if (strlen($trimmed) <= 8) {
            return $trimmed;
        }

        return substr($trimmed, 0, 4) . '…' . substr($trimmed, -4);
    }
}
