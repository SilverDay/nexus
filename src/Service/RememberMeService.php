<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\RememberMeServiceInterface;
use Nexus\DropInUser\Contract\TokenServiceInterface;
use PDO;

final class RememberMeService implements RememberMeServiceInterface
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly TokenServiceInterface $tokenService,
    ) {
    }

    public function issue(int $userId, int $ttlDays = 30): string
    {
        $selector = bin2hex(random_bytes(12));
        $validator = bin2hex(random_bytes(32));
        $validatorHash = $this->tokenService->hashToken($validator);

        $stmt = $this->pdo->prepare(
            'INSERT INTO remember_me_tokens (user_id, selector, validator_hash, expires_at)
             VALUES (:user_id, :selector, :validator_hash, DATE_ADD(UTC_TIMESTAMP(), INTERVAL :ttl DAY))'
        );
        $stmt->bindValue('user_id', $userId, PDO::PARAM_INT);
        $stmt->bindValue('selector', $selector, PDO::PARAM_STR);
        $stmt->bindValue('validator_hash', $validatorHash, PDO::PARAM_STR);
        $stmt->bindValue('ttl', $ttlDays, PDO::PARAM_INT);
        $stmt->execute();

        return $selector . ':' . $validator;
    }

    public function consumeAndRotate(string $cookieValue): ?array
    {
        [$selector, $validator] = $this->parseCookie($cookieValue);
        if ($selector === null || $validator === null) {
            return null;
        }

        $stmt = $this->pdo->prepare(
            'SELECT id, user_id, validator_hash
             FROM remember_me_tokens
             WHERE selector = :selector
               AND revoked_at IS NULL
               AND expires_at > UTC_TIMESTAMP()
             LIMIT 1'
        );
        $stmt->execute(['selector' => $selector]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!is_array($row) || !isset($row['id'], $row['user_id'], $row['validator_hash'])) {
            return null;
        }

        if (!hash_equals((string) $row['validator_hash'], $this->tokenService->hashToken($validator))) {
            $this->revokeBySelector($selector);
            return null;
        }

        $this->pdo->beginTransaction();
        try {
            $this->revokeBySelector($selector);
            $rotated = $this->issue((int) $row['user_id']);
            $this->pdo->commit();

            return ['userId' => (int) $row['user_id'], 'rotatedToken' => $rotated];
        } catch (\Throwable $exception) {
            $this->pdo->rollBack();
            throw $exception;
        }
    }

    public function revokeBySelector(string $selector): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE remember_me_tokens
             SET revoked_at = UTC_TIMESTAMP()
             WHERE selector = :selector AND revoked_at IS NULL'
        );
        $stmt->execute(['selector' => $selector]);
    }

    /**
     * @return array{0: string|null, 1: string|null}
     */
    private function parseCookie(string $cookieValue): array
    {
        $parts = explode(':', $cookieValue, 2);
        if (count($parts) !== 2) {
            return [null, null];
        }

        if ($parts[0] === '' || $parts[1] === '') {
            return [null, null];
        }

        return [$parts[0], $parts[1]];
    }
}
