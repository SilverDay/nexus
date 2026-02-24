<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Repository;

use Nexus\DropInUser\Contract\UserRepositoryInterface;
use PDO;

final class PdoUserRepository implements UserRepositoryInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function findByEmailOrUsername(string $identifier): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, username, email, real_name, password_hash, status, email_verified_at
             FROM users
             WHERE deleted_at IS NULL AND (username = :identifier OR email = :identifier)
             LIMIT 1'
        );
        $stmt->execute(['identifier' => $identifier]);
        $user = $stmt->fetch();

        return is_array($user) ? $user : null;
    }

    public function create(string $username, string $email, string $realName, string $passwordHash): array
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (username, email, real_name, password_hash) VALUES (:username, :email, :real_name, :password_hash)'
        );
        $stmt->execute([
            'username' => $username,
            'email' => $email,
            'real_name' => $realName,
            'password_hash' => $passwordHash,
        ]);

        return [
            'id' => (int) $this->pdo->lastInsertId(),
            'username' => $username,
            'email' => $email,
            'real_name' => $realName,
        ];
    }

    public function markEmailVerified(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users SET email_verified_at = CURRENT_TIMESTAMP WHERE id = :id'
        );
        $stmt->execute(['id' => $userId]);
    }
}
