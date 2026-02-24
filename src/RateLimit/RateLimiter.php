<?php

declare(strict_types=1);

namespace Nexus\DropInUser\RateLimit;

interface RateLimiter
{
    public function allow(string $bucket, int $limit, int $windowSeconds): bool;
}
