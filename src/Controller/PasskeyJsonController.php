<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Controller;

use Nexus\DropInUser\Contract\PasskeyServiceInterface;
use Nexus\DropInUser\Service\PasskeyCredentialService;

final class PasskeyJsonController
{
    public function __construct(
        private readonly PasskeyServiceInterface $passkeyService,
        private readonly PasskeyCredentialService $credentialService,
    ) {
    }

    /**
     * @return array{status:int, body:array<string,mixed>}
     */
    public function beginRegistration(int $userId): array
    {
        $options = $this->passkeyService->beginRegistration($userId);
        if ($options === []) {
            return [
                'status' => 400,
                'body' => [
                    'ok' => false,
                    'error' => 'Passkey registration is currently unavailable.',
                ],
            ];
        }

        return [
            'status' => 200,
            'body' => [
                'ok' => true,
                'options' => $options,
            ],
        ];
    }

    /**
     * @param array<string,mixed> $credential
     *
     * @return array{status:int, body:array<string,mixed>}
     */
    public function finishRegistration(int $userId, array $credential): array
    {
        $registered = $this->passkeyService->finishRegistration($userId, $credential);

        return [
            'status' => $registered ? 200 : 400,
            'body' => [
                'ok' => $registered,
                'message' => $registered
                    ? 'Passkey registered successfully.'
                    : 'Passkey registration could not be completed.',
            ],
        ];
    }

    /**
     * @return array{status:int, body:array<string,mixed>}
     */
    public function beginAuthentication(?int $userId): array
    {
        $options = $this->passkeyService->beginAuthentication($userId);
        if ($options === []) {
            return [
                'status' => 400,
                'body' => [
                    'ok' => false,
                    'error' => 'Passkey authentication is currently unavailable.',
                ],
            ];
        }

        return [
            'status' => 200,
            'body' => [
                'ok' => true,
                'options' => $options,
            ],
        ];
    }

    /**
     * @param array<string,mixed> $assertion
     *
     * @return array{status:int, body:array<string,mixed>}
     */
    public function finishAuthentication(array $assertion): array
    {
        $userId = $this->passkeyService->finishAuthentication($assertion);
        if ($userId === null || $userId <= 0) {
            return [
                'status' => 401,
                'body' => [
                    'ok' => false,
                    'error' => 'Passkey authentication failed.',
                ],
            ];
        }

        return [
            'status' => 200,
            'body' => [
                'ok' => true,
                'user_id' => $userId,
            ],
        ];
    }

    /**
     * @return array{status:int, body:array<string,mixed>}
     */
    public function listCredentials(int $userId): array
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
                'credentials' => $this->credentialService->listForUser($userId),
            ],
        ];
    }

    /**
     * @return array{status:int, body:array<string,mixed>}
     */
    public function revokeCredential(int $userId, string $credentialId): array
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

        $revoked = $this->credentialService->revokeForUser($userId, $credentialId);

        return [
            'status' => $revoked ? 200 : 400,
            'body' => [
                'ok' => $revoked,
                'message' => $revoked
                    ? 'Passkey revoked successfully.'
                    : 'Passkey could not be revoked.',
            ],
        ];
    }
}
