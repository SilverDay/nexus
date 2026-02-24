<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Config;

final class ModuleConfig
{
    public function __construct(
        public readonly string $dbDsn,
        public readonly string $dbUser,
        public readonly string $dbPassword,
        public readonly string $fromEmail,
        public readonly string $fromName,
        public readonly int $emailTokenTtlSeconds = 3600,
        public readonly int $passwordResetTokenTtlSeconds = 1800,
        public readonly bool $secureCookies = true,
        public readonly string $sameSite = 'Lax',
        public readonly string $ipBindingMode = 'subnet',
        public readonly bool $bindUserAgent = true,
        public readonly bool $exposeDebugTokens = false,
    ) {
    }
}
