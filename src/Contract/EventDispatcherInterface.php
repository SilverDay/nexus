<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface EventDispatcherInterface
{
    /**
     * @param array<string, mixed> $payload
     */
    public function dispatch(string $eventName, array $payload = []): void;
}
