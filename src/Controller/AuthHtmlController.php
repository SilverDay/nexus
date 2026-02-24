<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\AuthServiceInterface;
use Nexus\DropInUser\Contract\EmailVerificationServiceInterface;
use Nexus\DropInUser\Contract\PasswordResetServiceInterface;
use Nexus\DropInUser\Contract\ProfileFieldPolicyInterface;
use Nexus\DropInUser\Contract\TemplateRendererInterface;
use Nexus\DropInUser\Security\CsrfService;

final class AuthHtmlController
{
    public function __construct(
        private readonly TemplateRendererInterface $renderer,
        private readonly AuthServiceInterface $authService,
        private readonly EmailVerificationServiceInterface $emailVerification,
        private readonly PasswordResetServiceInterface $passwordReset,
        private readonly ProfileFieldPolicyInterface $profileFieldPolicy,
        private readonly CsrfService $csrf,
    ) {
    }

    public function showRegister(?string $message = null): string
    {
        $definitions = array_filter(
            $this->profileFieldPolicy->userFieldDefinitions(),
            static fn (array $definition): bool => ($definition['editable'] ?? false) === true
        );

        return $this->renderer->render('auth/register', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
            'profileFieldDefinitions' => $definitions,
        ]);
    }

    public function showLogin(?string $message = null): string
    {
        return $this->renderer->render('auth/login', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
        ]);
    }

    public function showVerifyEmail(?string $message = null): string
    {
        return $this->renderer->render('auth/verify_email', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
        ]);
    }

    public function showPasswordResetRequest(?string $message = null): string
    {
        return $this->renderer->render('auth/password_reset_request', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
        ]);
    }

    public function showPasswordResetConfirm(?string $message = null): string
    {
        return $this->renderer->render('auth/password_reset_confirm', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
        ]);
    }

    /**
     * @param array<string, mixed> $input
     */
    public function register(array $input): string
    {
        $profileFields = isset($input['profile']) && is_array($input['profile'])
            ? $input['profile']
            : [];

        $result = $this->authService->register(
            (string) ($input['username'] ?? ''),
            (string) ($input['email'] ?? ''),
            (string) ($input['realname'] ?? ''),
            (string) ($input['password'] ?? ''),
            $profileFields,
        );

        return $this->showRegister($result['message'] ?? null);
    }

    /**
     * @param array<string, mixed> $input
     */
    public function login(array $input): string
    {
        $result = $this->authService->login(
            (string) ($input['identifier'] ?? ''),
            (string) ($input['password'] ?? ''),
            (bool) ($input['remember_me'] ?? false),
        );

        return $this->showLogin($result['message'] ?? null);
    }

    /**
     * @param array<string, mixed> $input
     */
    public function verifyEmail(array $input): string
    {
        $ok = $this->emailVerification->consume((string) ($input['token'] ?? ''));
        $message = $ok ? 'Email verified.' : 'Invalid verification token.';

        return $this->showVerifyEmail($message);
    }

    /**
     * @param array<string, mixed> $input
     */
    public function requestPasswordReset(array $input): string
    {
        $this->passwordReset->request((string) ($input['identifier'] ?? ''));

        return $this->showPasswordResetRequest('If the account exists, reset instructions were sent.');
    }

    /**
     * @param array<string, mixed> $input
     */
    public function confirmPasswordReset(array $input): string
    {
        $ok = $this->passwordReset->consume(
            (string) ($input['token'] ?? ''),
            (string) ($input['new_password'] ?? ''),
        );

        return $this->showPasswordResetConfirm(
            $ok ? 'Password updated.' : 'Invalid token or password policy failure.'
        );
    }
}
