<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\RiskEngineInterface;
use Nexus\DropInUser\Contract\SessionManagerInterface;
use Nexus\DropInUser\Observability\RequestContext;
use Nexus\DropInUser\Risk\RiskDecision;
use PDO;

/**
 * Validates and maintains active sessions using risk-engine decisions.
 *
 * On non-allow decisions, the current session is revoked immediately.
 */
final class SessionManager implements SessionManagerInterface
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly RiskEngineInterface $riskEngine,
        private readonly RequestContext $requestContext,
        private readonly string $ipBindingMode,
        private readonly bool $bindUserAgent,
    ) {
    }

    /**
     * Validates the current PHP session ID for the provided user and updates
     * `last_seen_at` on success.
     */
    public function validateCurrentSession(int $userId): bool
    {
        $sessionId = session_id();
        if ($sessionId === '') {
            return false;
        }

        $stmt = $this->pdo->prepare(
            'SELECT id, ip_address, ua_hash
             FROM user_sessions
             WHERE user_id = :user_id AND session_id = :session_id AND revoked_at IS NULL
             LIMIT 1'
        );
        $stmt->execute([
            'user_id' => $userId,
            'session_id' => $sessionId,
        ]);

        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row) || !isset($row['id'])) {
            return false;
        }

        $decision = $this->riskEngine->assess(
            $row,
            $this->requestContext->sourceIp(),
            $this->requestContext->userAgentHash(),
            $this->ipBindingMode,
            $this->bindUserAgent,
        );

        if ($decision !== RiskDecision::ALLOW) {
            $this->revokeSessionById($sessionId);
            return false;
        }

        $touch = $this->pdo->prepare('UPDATE user_sessions SET last_seen_at = UTC_TIMESTAMP() WHERE id = :id');
        $touch->execute(['id' => (int) $row['id']]);

        return true;
    }

    /**
     * Revokes the given session identifier if it is still active.
     */
    public function revokeSessionById(string $sessionId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE user_sessions
             SET revoked_at = UTC_TIMESTAMP()
             WHERE session_id = :session_id AND revoked_at IS NULL'
        );
        $stmt->execute(['session_id' => $sessionId]);
    }
}
