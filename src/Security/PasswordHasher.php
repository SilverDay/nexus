<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Security;

final class PasswordHasher
{
    public function hash(string $password): string
    {
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;

        return password_hash($password, $algo);
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
}
