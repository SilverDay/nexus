<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\RecoveryCodeServiceInterface;

final class NullRecoveryCodeService implements RecoveryCodeServiceInterface
{
    public function regenerateCodes(int $userId): array
    {
        return [];
    }

    public function consumeCode(int $userId, string $code): bool
    {
        return false;
    }
}
