<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\PasswordResetServiceInterface;
use Nexus\DropInUser\Contract\TokenServiceInterface;
use Nexus\DropInUser\Contract\UserRepositoryInterface;
use Nexus\DropInUser\Observability\RequestContext;
use Nexus\DropInUser\Security\PasswordHasher;
use PDO;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class PasswordResetService implements PasswordResetServiceInterface
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly PDO $pdo,
        private readonly UserRepositoryInterface $users,
        private readonly TokenServiceInterface $tokenService,
        private readonly PasswordHasher $passwordHasher,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
        private readonly int $ttlSeconds = 1800,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function request(string $identifier): ?string
    {
        $context = $this->requestContext->asAuditContext();
        $user = $this->users->findByEmailOrUsername($identifier);
        if ($user === null || !isset($user['id'])) {
            $this->logger->notice('auth.password_reset.request_ignored', ['request_id' => $context['request_id']]);
            return null;
        }

        $token = $this->tokenService->generateToken();
        $tokenHash = $this->tokenService->hashToken($token);

        $stmt = $this->pdo->prepare(
            'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES (:user_id, :token_hash, DATE_ADD(UTC_TIMESTAMP(), INTERVAL :ttl SECOND))'
        );
        $stmt->bindValue('user_id', (int) $user['id'], PDO::PARAM_INT);
        $stmt->bindValue('token_hash', $tokenHash, PDO::PARAM_STR);
        $stmt->bindValue('ttl', $this->ttlSeconds, PDO::PARAM_INT);
        $stmt->execute();

        $this->auditLogger->log('auth.password_reset.requested', (int) $user['id'], (int) $user['id'], $context);
        $this->logger->info('auth.password_reset.requested', [
            'user_id' => (int) $user['id'],
            'request_id' => $context['request_id'],
        ]);

        return $token;
    }

    public function consume(string $token, string $newPassword): bool
    {
        $context = $this->requestContext->asAuditContext();
        if (mb_strlen($newPassword) < 12) {
            return false;
        }

        $tokenHash = $this->tokenService->hashToken($token);

        $select = $this->pdo->prepare(
            'SELECT id, user_id
             FROM password_reset_tokens
             WHERE token_hash = :token_hash
               AND consumed_at IS NULL
               AND expires_at > UTC_TIMESTAMP()
             LIMIT 1'
        );
        $select->execute(['token_hash' => $tokenHash]);
        $row = $select->fetch(PDO::FETCH_ASSOC);

        if (!is_array($row) || !isset($row['id'], $row['user_id'])) {
            $this->logger->notice('auth.password_reset.consume_failed', ['request_id' => $context['request_id']]);
            return false;
        }

        $this->pdo->beginTransaction();
        try {
            $passwordHash = $this->passwordHasher->hash($newPassword);

            $updateUser = $this->pdo->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id');
            $updateUser->execute([
                'password_hash' => $passwordHash,
                'id' => (int) $row['user_id'],
            ]);

            $consumeToken = $this->pdo->prepare(
                'UPDATE password_reset_tokens
                 SET consumed_at = UTC_TIMESTAMP()
                 WHERE id = :id AND consumed_at IS NULL'
            );
            $consumeToken->execute(['id' => (int) $row['id']]);

            $revokeRemember = $this->pdo->prepare(
                'UPDATE remember_me_tokens
                 SET revoked_at = UTC_TIMESTAMP()
                 WHERE user_id = :user_id AND revoked_at IS NULL'
            );
            $revokeRemember->execute(['user_id' => (int) $row['user_id']]);

            $this->pdo->commit();

            $this->auditLogger->log('auth.password_reset.completed', (int) $row['user_id'], (int) $row['user_id'], $context);
            $this->logger->info('auth.password_reset.completed', [
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
