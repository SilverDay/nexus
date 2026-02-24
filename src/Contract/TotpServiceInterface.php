<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface TotpServiceInterface
{
    public function beginEnrollment(int $userId): string;

    public function confirmEnrollment(int $userId, string $otpCode): bool;

    public function verifyCode(int $userId, string $otpCode): bool;
}
