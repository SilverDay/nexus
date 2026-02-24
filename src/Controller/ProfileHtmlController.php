<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\ProfileServiceInterface;
use Nexus\DropInUser\Contract\TemplateRendererInterface;
use Nexus\DropInUser\Security\CsrfService;

final class ProfileHtmlController
{
    public function __construct(
        private readonly ProfileServiceInterface $profileService,
        private readonly TemplateRendererInterface $renderer,
        private readonly CsrfService $csrf,
    ) {
    }

    public function show(int $userId, ?string $message = null): string
    {
        $profile = $this->profileService->getProfile($userId);

        return $this->renderer->render('auth/profile', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
            'user' => $profile['user'],
            'profileFields' => $profile['profile_fields'],
            'profileFieldDefinitions' => $profile['profile_field_definitions'],
        ]);
    }

    /**
     * @param array<string, mixed> $input
     */
    public function update(int $userId, array $input): string
    {
        $profileFields = isset($input['profile']) && is_array($input['profile'])
            ? $input['profile']
            : [];

        $ok = $this->profileService->updateProfile(
            $userId,
            (string) ($input['realname'] ?? ''),
            $profileFields,
        );

        return $this->show($userId, $ok ? 'Profile updated.' : 'Unable to update profile.');
    }
}
