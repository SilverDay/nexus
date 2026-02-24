<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface OidcProviderInterface
{
    public function authorizationUrl(string $state, string $nonce): string;

    /**
     * @return array<string, mixed>
     */
    public function exchangeCode(string $code): array;

    /**
     * @param array<string, mixed> $tokenSet
     * @return array<string, mixed>
     */
    public function fetchUserProfile(array $tokenSet): array;
}
