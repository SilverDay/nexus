<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\RecoveryCodeServiceInterface;
use Nexus\DropInUser\Contract\StepUpServiceInterface;
use Nexus\DropInUser\Contract\TemplateRendererInterface;
use Nexus\DropInUser\Contract\TotpServiceInterface;
use Nexus\DropInUser\Security\CsrfService;

final class TotpHtmlController
{
    public function __construct(
        private readonly TemplateRendererInterface $renderer,
        private readonly TotpServiceInterface $totpService,
        private readonly RecoveryCodeServiceInterface $recoveryCodes,
        private readonly StepUpServiceInterface $stepUpService,
        private readonly CsrfService $csrf,
    ) {
    }

    /**
     * @param list<string> $recoveryCodes
     */
    public function showEnrollment(?string $message = null, ?string $provisioningUri = null, array $recoveryCodes = []): string
    {
        return $this->renderer->render('auth/totp_enroll', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
            'provisioningUri' => $provisioningUri,
            'recoveryCodes' => $recoveryCodes,
        ]);
    }

    /**
     * @param array<string, mixed> $input
     */
    public function beginEnrollment(int $userId, array $input = []): string
    {
        try {
            $uri = $this->totpService->beginEnrollment($userId);
            return $this->showEnrollment('TOTP enrollment started. Scan the provisioning URI in your authenticator app.', $uri);
        } catch (\RuntimeException) {
            return $this->showEnrollment('Unable to start TOTP enrollment.');
        }
    }

    /**
     * @param array<string, mixed> $input
     */
    public function confirmEnrollment(int $userId, array $input): string
    {
        $ok = $this->totpService->confirmEnrollment(
            $userId,
            (string) ($input['otp'] ?? $input['otp_code'] ?? '')
        );

        return $this->showEnrollment(
            $ok ? 'TOTP enrollment confirmed.' : 'Unable to confirm TOTP enrollment.'
        );
    }

    public function regenerateRecoveryCodes(int $userId): string
    {
        $codes = $this->recoveryCodes->regenerateCodes($userId);

        return $this->showEnrollment(
            $codes === [] ? 'Unable to regenerate recovery codes.' : 'Recovery codes regenerated. Save them securely.',
            null,
            $codes,
        );
    }

    public function showStepUp(?string $message = null): string
    {
        return $this->renderer->render('auth/step_up_verify', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
        ]);
    }

    /**
     * @param array<string, mixed> $input
     */
    public function verifyStepUp(array $input): string
    {
        $ok = $this->stepUpService->verifyChallenge(0, $input);

        return $this->showStepUp(
            $ok ? 'Step-up verification successful.' : 'Invalid verification code.'
        );
    }
}
