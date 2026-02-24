<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface PasskeyCeremonyValidatorInterface
{
    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public function createRegistrationOptions(array $context): array;

    /**
     * @param array<string, mixed> $context
     * @param array<string, mixed> $attestationResponse
     * @return array<string, mixed>|null
     */
    public function validateRegistrationResponse(array $context, array $attestationResponse): ?array;

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public function createAuthenticationOptions(array $context): array;

    /**
     * @param array<string, mixed> $context
     * @param array<string, mixed> $assertionResponse
     * @return array<string, mixed>|null
     */
    public function validateAuthenticationResponse(array $context, array $assertionResponse): ?array;
}
