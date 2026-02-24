<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface RememberMeServiceInterface
{
    public function issue(int $userId, int $ttlDays = 30): string;

    /**
     * @return array{userId: int, rotatedToken: string}|null
     */
    public function consumeAndRotate(string $cookieValue): ?array;

    public function revokeBySelector(string $selector): void;
}
