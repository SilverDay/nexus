<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\TemplateRendererInterface;
use Nexus\DropInUser\Security\CsrfService;
use Nexus\DropInUser\Service\PasskeyCredentialService;

final class PasskeyHtmlController
{
    public function __construct(
        private readonly TemplateRendererInterface $renderer,
        private readonly PasskeyCredentialService $credentialService,
        private readonly CsrfService $csrf,
    ) {
    }

    public function show(int $userId, ?string $message = null): string
    {
        return $this->renderer->render('auth/passkeys', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
            'credentials' => $this->credentialService->listForUser($userId),
        ]);
    }

    public function revoke(int $userId, string $credentialId): string
    {
        $ok = $this->credentialService->revokeForUser($userId, $credentialId);

        return $this->show($userId, $ok ? 'Passkey revoked successfully.' : 'Passkey could not be revoked.');
    }
}
