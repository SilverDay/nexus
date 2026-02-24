<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface PasskeyServiceInterface
{
    /**
     * @return array<string, mixed>
     */
    public function beginRegistration(int $userId): array;

    /**
     * @param array<string, mixed> $attestationResponse
     */
    public function finishRegistration(int $userId, array $attestationResponse): bool;

    /**
     * @return array<string, mixed>
     */
    public function beginAuthentication(?int $userId = null): array;

    /**
     * @param array<string, mixed> $assertionResponse
     */
    public function finishAuthentication(array $assertionResponse): ?int;
}
