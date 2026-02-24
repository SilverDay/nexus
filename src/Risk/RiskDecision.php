<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Risk;

final class RiskDecision
{
    public const ALLOW = 'allow';
    public const REQUIRE_STEP_UP = 'require_step_up';
    public const DENY = 'deny';
}
