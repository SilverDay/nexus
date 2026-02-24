<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface StepUpServiceInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function startChallenge(int $userId, array $context = []): bool;

    /**
     * @param array<string, mixed> $input
     */
    public function verifyChallenge(int $userId, array $input): bool;
}
