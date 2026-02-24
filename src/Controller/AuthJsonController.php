<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\AuthServiceInterface;

final class AuthJsonController
{
    public function __construct(private readonly AuthServiceInterface $authService)
    {
    }

    /**
     * @param array<string, mixed> $input
     * @return array{status: int, body: array<string, mixed>}
     */
    public function register(array $input): array
    {
        $profileFields = isset($input['profile_fields']) && is_array($input['profile_fields'])
            ? $input['profile_fields']
            : [];

        $result = $this->authService->register(
            (string) ($input['username'] ?? ''),
            (string) ($input['email'] ?? ''),
            (string) ($input['realname'] ?? ''),
            (string) ($input['password'] ?? ''),
            $profileFields,
        );

        return ['status' => $result['ok'] ? 200 : 400, 'body' => $result];
    }

    /**
     * @param array<string, mixed> $input
     * @return array{status: int, body: array<string, mixed>}
     */
    public function login(array $input): array
    {
        $result = $this->authService->login(
            (string) ($input['identifier'] ?? ''),
            (string) ($input['password'] ?? ''),
            (bool) ($input['remember_me'] ?? false),
        );

        return ['status' => $result['ok'] ? 200 : 401, 'body' => $result];
    }
}
