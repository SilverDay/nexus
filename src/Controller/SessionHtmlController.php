<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\TemplateRendererInterface;
use Nexus\DropInUser\Security\CsrfService;
use Nexus\DropInUser\Service\SessionDeviceService;

final class SessionHtmlController
{
    public function __construct(
        private readonly TemplateRendererInterface $renderer,
        private readonly SessionDeviceService $sessionService,
        private readonly CsrfService $csrf,
    ) {
    }

    public function show(int $userId, string $currentSessionId, ?string $message = null): string
    {
        return $this->renderer->render('auth/sessions', [
            'csrfToken' => $this->csrf->token(),
            'message' => $message,
            'sessions' => $this->sessionService->listForUser($userId, $currentSessionId),
        ]);
    }

    public function revoke(int $userId, string $currentSessionId, string $sessionId): string
    {
        $ok = $this->sessionService->revokeForUser($userId, $sessionId);

        return $this->show($userId, $currentSessionId, $ok ? 'Session revoked successfully.' : 'Session could not be revoked.');
    }
}
