<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface SessionManagerInterface
{
    public function validateCurrentSession(int $userId): bool;

    public function revokeSessionById(string $sessionId): void;
}
