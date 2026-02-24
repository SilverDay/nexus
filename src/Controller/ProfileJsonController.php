<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\ProfileServiceInterface;

final class ProfileJsonController
{
    public function __construct(private readonly ProfileServiceInterface $profileService)
    {
    }

    public function get(int $userId): array
    {
        return [
            'status' => 200,
            'body' => ['ok' => true] + $this->profileService->getProfile($userId),
        ];
    }

    /**
     * @param array<string, mixed> $input
     */
    public function update(int $userId, array $input): array
    {
        $profileFields = isset($input['profile_fields']) && is_array($input['profile_fields'])
            ? $input['profile_fields']
            : [];

        $ok = $this->profileService->updateProfile(
            $userId,
            (string) ($input['realname'] ?? ''),
            $profileFields,
        );

        return ['status' => $ok ? 200 : 400, 'body' => ['ok' => $ok]];
    }
}
