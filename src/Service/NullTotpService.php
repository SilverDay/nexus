<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\TotpServiceInterface;

final class NullTotpService implements TotpServiceInterface
{
    public function beginEnrollment(int $userId): string
    {
        throw new \RuntimeException('TOTP is not configured.');
    }

    public function confirmEnrollment(int $userId, string $otpCode): bool
    {
        return false;
    }

    public function verifyCode(int $userId, string $otpCode): bool
    {
        return false;
    }
}
