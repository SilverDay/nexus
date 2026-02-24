<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface PasswordResetServiceInterface
{
    public function request(string $identifier): ?string;

    public function consume(string $token, string $newPassword): bool;
}
