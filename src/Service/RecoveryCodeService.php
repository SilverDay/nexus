<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\RecoveryCodeServiceInterface;
use Nexus\DropInUser\Contract\TokenServiceInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;

final class RecoveryCodeService implements RecoveryCodeServiceInterface
{
    private const DEFAULT_COUNT = 10;

    public function __construct(
        private readonly PDO $pdo,
        private readonly TokenServiceInterface $tokenService,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
    ) {
    }

    public function regenerateCodes(int $userId): array
    {
        if ($userId <= 0) {
            return [];
        }

        $codes = [];
        $this->pdo->beginTransaction();
        try {
            $delete = $this->pdo->prepare('DELETE FROM user_recovery_codes WHERE user_id = :user_id');
            $delete->execute(['user_id' => $userId]);

            $insert = $this->pdo->prepare(
                'INSERT INTO user_recovery_codes (user_id, code_hash)
                 VALUES (:user_id, :code_hash)'
            );

            for ($i = 0; $i < self::DEFAULT_COUNT; $i++) {
                $raw = strtoupper(bin2hex(random_bytes(4)));
                $code = substr($raw, 0, 4) . '-' . substr($raw, 4, 4);
                $codes[] = $code;

                $insert->execute([
                    'user_id' => $userId,
                    'code_hash' => $this->tokenService->hashToken($this->normalizeCode($code)),
                ]);
            }

            $this->pdo->commit();
        } catch (\Throwable $exception) {
            $this->pdo->rollBack();
            throw $exception;
        }

        $context = $this->requestContext->asAuditContext();
        $this->auditLogger->log('auth.recovery_codes.regenerated', $userId, $userId, $context);

        return $codes;
    }

    public function consumeCode(int $userId, string $code): bool
    {
        if ($userId <= 0) {
            return false;
        }

        $hash = $this->tokenService->hashToken($this->normalizeCode($code));
        $stmt = $this->pdo->prepare(
            'UPDATE user_recovery_codes
             SET consumed_at = UTC_TIMESTAMP()
             WHERE user_id = :user_id
               AND code_hash = :code_hash
               AND consumed_at IS NULL'
        );
        $stmt->execute([
            'user_id' => $userId,
            'code_hash' => $hash,
        ]);

        $ok = $stmt->rowCount() > 0;
        if ($ok) {
            $context = $this->requestContext->asAuditContext();
            $this->auditLogger->log('auth.recovery_code.consumed', $userId, $userId, $context);
        }

        return $ok;
    }

    private function normalizeCode(string $code): string
    {
        return strtoupper(preg_replace('/[^A-Z0-9]/i', '', $code) ?? '');
    }
}
