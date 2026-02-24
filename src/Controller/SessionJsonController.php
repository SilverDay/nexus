<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Service\SessionDeviceService;

final class SessionJsonController
{
    public function __construct(private readonly SessionDeviceService $sessionService)
    {
    }

    /**
     * @return array{status:int, body:array<string,mixed>}
     */
    public function list(int $userId, string $currentSessionId): array
    {
        if ($userId <= 0) {
            return [
                'status' => 401,
                'body' => [
                    'ok' => false,
                    'message' => 'Unauthorized',
                ],
            ];
        }

        return [
            'status' => 200,
            'body' => [
                'ok' => true,
                'sessions' => $this->sessionService->listForUser($userId, $currentSessionId),
            ],
        ];
    }

    /**
     * @return array{status:int, body:array<string,mixed>}
     */
    public function revoke(int $userId, string $sessionId): array
    {
        if ($userId <= 0) {
            return [
                'status' => 401,
                'body' => [
                    'ok' => false,
                    'message' => 'Unauthorized',
                ],
            ];
        }

        $ok = $this->sessionService->revokeForUser($userId, $sessionId);

        return [
            'status' => $ok ? 200 : 400,
            'body' => [
                'ok' => $ok,
                'message' => $ok ? 'Session revoked successfully.' : 'Session could not be revoked.',
            ],
        ];
    }
}
