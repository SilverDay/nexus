<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface SecurityHeadersInterface
{
    public function emit(): void;
}
