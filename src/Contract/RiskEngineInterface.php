<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface RiskEngineInterface
{
    /**
     * @param array<string, mixed>|null $lastSession
     */
    public function assess(
        ?array $lastSession,
        string $currentIp,
        string $currentUserAgentHash,
        string $ipBindingMode,
        bool $bindUserAgent,
    ): string;
}
