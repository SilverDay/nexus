<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\PasskeyCeremonyValidatorInterface;

final class NullPasskeyCeremonyValidator implements PasskeyCeremonyValidatorInterface
{
    public function createRegistrationOptions(array $context): array
    {
        return [];
    }

    public function validateRegistrationResponse(array $context, array $attestationResponse): ?array
    {
        return null;
    }

    public function createAuthenticationOptions(array $context): array
    {
        return [];
    }

    public function validateAuthenticationResponse(array $context, array $assertionResponse): ?array
    {
        return null;
    }
}
