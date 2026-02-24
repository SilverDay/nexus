<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface UserRepositoryInterface
{
    /**
     * @return array<string, mixed>|null
     */
    public function findByEmailOrUsername(string $identifier): ?array;

    /**
     * @return array<string, mixed>
     */
    public function create(string $username, string $email, string $realName, string $passwordHash): array;

    public function markEmailVerified(int $userId): void;
}
