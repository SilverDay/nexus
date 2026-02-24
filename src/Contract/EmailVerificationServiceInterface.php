<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface EmailVerificationServiceInterface
{
    public function createForUser(int $userId): string;

    public function consume(string $token): bool;
}
