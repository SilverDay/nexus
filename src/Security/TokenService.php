<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Security;

use Nexus\DropInUser\Contract\TokenServiceInterface;

final class TokenService implements TokenServiceInterface
{
    public function generateToken(int $length = 32): string
    {
        return bin2hex(random_bytes($length));
    }

    public function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    public function hashUserAgent(string $userAgent): string
    {
        return hash('sha256', $userAgent);
    }
}
