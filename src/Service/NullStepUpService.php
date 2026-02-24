<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\StepUpServiceInterface;

final class NullStepUpService implements StepUpServiceInterface
{
    public function startChallenge(int $userId, array $context = []): bool
    {
        return false;
    }

    public function verifyChallenge(int $userId, array $input): bool
    {
        return false;
    }
}
