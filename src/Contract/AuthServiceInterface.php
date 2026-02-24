<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface AuthServiceInterface
{
    /**
     * @return array{ok: bool, message: string}
     */
    public function register(string $username, string $email, string $realName, string $password, array $profileFields = []): array;

    /**
     * @return array{ok: bool, message: string, userId?: int, rememberMeToken?: string}
     */
    public function login(string $identifier, string $password, bool $rememberMe = false): array;
}
