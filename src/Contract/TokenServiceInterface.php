<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface TokenServiceInterface
{
    public function generateToken(int $length = 32): string;

    public function hashToken(string $token): string;

    public function hashUserAgent(string $userAgent): string;
}
