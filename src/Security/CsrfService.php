<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Security;

final class CsrfService
{
    private const SESSION_KEY = '_nexus_csrf';

    public function token(): string
    {
        if (!isset($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = bin2hex(random_bytes(32));
        }

        return (string) $_SESSION[self::SESSION_KEY];
    }

    public function validate(?string $providedToken): bool
    {
        if (!is_string($providedToken) || $providedToken === '') {
            return false;
        }

        $currentToken = $_SESSION[self::SESSION_KEY] ?? '';
        if (!is_string($currentToken) || $currentToken === '') {
            return false;
        }

        return hash_equals($currentToken, $providedToken);
    }
}
