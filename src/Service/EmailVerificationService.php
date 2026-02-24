<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\EmailVerificationServiceInterface;
use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\TokenServiceInterface;
use Nexus\DropInUser\Contract\UserRepositoryInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class EmailVerificationService implements EmailVerificationServiceInterface
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly PDO $pdo,
        private readonly TokenServiceInterface $tokenService,
        private readonly UserRepositoryInterface $users,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
        private readonly int $ttlSeconds = 3600,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function createForUser(int $userId): string
    {
        $context = $this->requestContext->asAuditContext();
        $token = $this->tokenService->generateToken();
        $tokenHash = $this->tokenService->hashToken($token);

        $stmt = $this->pdo->prepare(
            'INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
             VALUES (:user_id, :token_hash, DATE_ADD(UTC_TIMESTAMP(), INTERVAL :ttl SECOND))'
        );
        $stmt->bindValue('user_id', $userId, PDO::PARAM_INT);
        $stmt->bindValue('token_hash', $tokenHash, PDO::PARAM_STR);
        $stmt->bindValue('ttl', $this->ttlSeconds, PDO::PARAM_INT);
        $stmt->execute();

        $this->auditLogger->log('auth.email_verification.issued', $userId, $userId, $context);
        $this->logger->info('auth.email_verification.issued', [
            'user_id' => $userId,
            'request_id' => $context['request_id'],
        ]);

        return $token;
    }

    public function consume(string $token): bool
    {
        $context = $this->requestContext->asAuditContext();
        $tokenHash = $this->tokenService->hashToken($token);

        $select = $this->pdo->prepare(
            'SELECT id, user_id
             FROM email_verification_tokens
             WHERE token_hash = :token_hash
               AND consumed_at IS NULL
               AND expires_at > UTC_TIMESTAMP()
             LIMIT 1'
        );
        $select->execute(['token_hash' => $tokenHash]);
        $row = $select->fetch(PDO::FETCH_ASSOC);

        if (!is_array($row) || !isset($row['id'], $row['user_id'])) {
            $this->logger->notice('auth.email_verification.failed', ['request_id' => $context['request_id']]);
            return false;
        }

        $this->pdo->beginTransaction();
        try {
            $update = $this->pdo->prepare(
                'UPDATE email_verification_tokens
                 SET consumed_at = UTC_TIMESTAMP()
                 WHERE id = :id AND consumed_at IS NULL'
            );
            $update->execute(['id' => (int) $row['id']]);

            if ($update->rowCount() !== 1) {
                $this->pdo->rollBack();
                return false;
            }

            $this->users->markEmailVerified((int) $row['user_id']);
            $this->pdo->commit();

            $this->auditLogger->log('auth.email_verified', (int) $row['user_id'], (int) $row['user_id'], $context);
            $this->logger->info('auth.email_verified', [
                'user_id' => (int) $row['user_id'],
                'request_id' => $context['request_id'],
            ]);

            return true;
        } catch (\Throwable $exception) {
            $this->pdo->rollBack();
            throw $exception;
        }
    }
}
