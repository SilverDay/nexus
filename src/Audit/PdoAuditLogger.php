<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Audit;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use PDO;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class PdoAuditLogger implements AuditLoggerInterface
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly PDO $pdo,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function log(string $eventType, ?int $actorUserId, ?int $targetUserId, array $context = []): void
    {
        $safeContext = $this->sanitizeContext($context);

        $stmt = $this->pdo->prepare(
            'INSERT INTO audit_logs (
                event_type,
                actor_user_id,
                target_user_id,
                source_ip,
                user_agent_hash,
                request_id,
                context_json
            ) VALUES (
                :event_type,
                :actor_user_id,
                :target_user_id,
                :source_ip,
                :user_agent_hash,
                :request_id,
                :context_json
            )'
        );

        $stmt->execute([
            'event_type' => $eventType,
            'actor_user_id' => $actorUserId,
            'target_user_id' => $targetUserId,
            'source_ip' => $context['source_ip'] ?? null,
            'user_agent_hash' => $context['user_agent_hash'] ?? null,
            'request_id' => $context['request_id'] ?? null,
            'context_json' => json_encode($safeContext, JSON_THROW_ON_ERROR),
        ]);

        $this->logger->info('security.audit_event', [
            'event_type' => $eventType,
            'actor_user_id' => $actorUserId,
            'target_user_id' => $targetUserId,
            'request_id' => $context['request_id'] ?? null,
        ]);
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    private function sanitizeContext(array $context): array
    {
        $blockedKeys = ['password', 'token', 'validator', 'secret'];

        foreach ($blockedKeys as $key) {
            if (array_key_exists($key, $context)) {
                unset($context[$key]);
            }
        }

        return $context;
    }
}
