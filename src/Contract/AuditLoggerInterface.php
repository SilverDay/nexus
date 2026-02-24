<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface AuditLoggerInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function log(string $eventType, ?int $actorUserId, ?int $targetUserId, array $context = []): void;
}
