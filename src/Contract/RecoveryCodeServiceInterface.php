<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface RecoveryCodeServiceInterface
{
    /**
     * @return list<string>
     */
    public function regenerateCodes(int $userId): array;

    public function consumeCode(int $userId, string $code): bool;
}
