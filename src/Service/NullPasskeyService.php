<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\PasskeyServiceInterface;

final class NullPasskeyService implements PasskeyServiceInterface
{
    public function beginRegistration(int $userId): array
    {
        return [];
    }

    public function finishRegistration(int $userId, array $credential): bool
    {
        return false;
    }

    public function beginAuthentication(?int $userId = null): array
    {
        return [];
    }

    public function finishAuthentication(array $assertion): ?int
    {
        return null;
    }
}
