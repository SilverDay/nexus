<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Event;

use Nexus\DropInUser\Contract\EventDispatcherInterface;

final class NullEventDispatcher implements EventDispatcherInterface
{
    public function dispatch(string $eventName, array $payload = []): void
    {
    }
}
