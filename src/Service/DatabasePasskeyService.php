<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\PasskeyCeremonyValidatorInterface;
use Nexus\DropInUser\Contract\PasskeyServiceInterface;
use Nexus\DropInUser\Contract\TokenServiceInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;

final class DatabasePasskeyService implements PasskeyServiceInterface
{
    private const CHALLENGE_TTL_SECONDS = 300;

    public function __construct(
        private readonly PDO $pdo,
        private readonly TokenServiceInterface $tokenService,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
        private readonly PasskeyCeremonyValidatorInterface $validator,
        private readonly string $rpId,
        private readonly string $rpOrigin,
        private readonly string $rpName = 'Nexus User Module',
    ) {
    }

    public function beginRegistration(int $userId): array
    {
        if ($userId <= 0) {
            return [];
        }

        $user = $this->findActiveUser($userId);
        if ($user === null) {
            return [];
        }

        $challenge = $this->generateChallenge();
        $options = $this->validator->createRegistrationOptions([
            'challenge' => $challenge,
            'rp_id' => $this->rpId,
            'rp_origin' => $this->rpOrigin,
            'rp_name' => $this->rpName,
            'user' => $user,
            'exclude_credential_ids' => $this->listCredentialIdsForUser($userId),
        ]);

        if ($options === []) {
            return [];
        }

        if (!$this->storeChallenge($challenge, $userId, 'register')) {
            return [];
        }

        return $options;
    }

    public function finishRegistration(int $userId, array $attestationResponse): bool
    {
        if ($userId <= 0) {
            return false;
        }

        $challenge = $this->extractChallenge($attestationResponse);
        if ($challenge === '') {
            return false;
        }

        if (!$this->consumeChallenge($challenge, $userId, 'register')) {
            return false;
        }

        $user = $this->findActiveUser($userId);
        if ($user === null) {
            return false;
        }

        $validated = $this->validator->validateRegistrationResponse([
            'rp_id' => $this->rpId,
            'rp_origin' => $this->rpOrigin,
            'user_id' => $userId,
            'challenge' => $challenge,
            'user' => $user,
        ], $attestationResponse);

        if (!is_array($validated)) {
            return false;
        }

        $credentialId = isset($validated['credential_id']) ? trim((string) $validated['credential_id']) : '';
        $publicKey = isset($validated['public_key']) ? trim((string) $validated['public_key']) : '';
        if ($credentialId === '' || $publicKey === '') {
            return false;
        }

        $signCount = max(0, (int) ($validated['sign_count'] ?? 0));
        $aaguid = isset($validated['aaguid']) ? trim((string) $validated['aaguid']) : null;
        $label = isset($validated['label']) ? trim((string) $validated['label']) : null;
        $transports = $this->normalizeTransports($validated['transports'] ?? null);

        $stmt = $this->pdo->prepare(
            'INSERT INTO user_passkey_credentials (user_id, credential_id, public_key, sign_count, transports, aaguid, credential_label)
             VALUES (:user_id, :credential_id, :public_key, :sign_count, :transports, :aaguid, :credential_label)
             ON DUPLICATE KEY UPDATE
               user_id = VALUES(user_id),
               public_key = VALUES(public_key),
               sign_count = VALUES(sign_count),
               transports = VALUES(transports),
               aaguid = VALUES(aaguid),
               credential_label = VALUES(credential_label),
               updated_at = CURRENT_TIMESTAMP'
        );

        $ok = $stmt->execute([
            'user_id' => $userId,
            'credential_id' => $credentialId,
            'public_key' => $publicKey,
            'sign_count' => $signCount,
            'transports' => $transports,
            'aaguid' => $aaguid,
            'credential_label' => $label,
        ]);

        if (!$ok) {
            return false;
        }

        $context = $this->requestContext->asAuditContext();
        $this->auditLogger->log('auth.passkey.registered', $userId, $userId, $context);

        return true;
    }

    public function beginAuthentication(?int $userId = null): array
    {
        if ($userId !== null && $userId <= 0) {
            return [];
        }

        $challenge = $this->generateChallenge();
        $allowedCredentials = $userId !== null
            ? $this->listCredentialIdsForUser($userId)
            : [];

        $options = $this->validator->createAuthenticationOptions([
            'challenge' => $challenge,
            'rp_id' => $this->rpId,
            'rp_origin' => $this->rpOrigin,
            'user_id' => $userId,
            'allowed_credential_ids' => $allowedCredentials,
        ]);

        if ($options === []) {
            return [];
        }

        if (!$this->storeChallenge($challenge, $userId, 'authenticate')) {
            return [];
        }

        return $options;
    }

    public function finishAuthentication(array $assertionResponse): ?int
    {
        $challenge = $this->extractChallenge($assertionResponse);
        if ($challenge === '') {
            return null;
        }

        $hintUserId = isset($assertionResponse['user_id']) ? (int) $assertionResponse['user_id'] : null;
        if (!$this->consumeChallenge($challenge, $hintUserId, 'authenticate')) {
            return null;
        }

        $credentialId = $this->extractCredentialId($assertionResponse);
        $storedCredential = $credentialId !== '' ? $this->findCredentialById($credentialId) : null;

        $validated = $this->validator->validateAuthenticationResponse([
            'challenge' => $challenge,
            'rp_id' => $this->rpId,
            'rp_origin' => $this->rpOrigin,
            'hint_user_id' => $hintUserId,
            'stored_credential' => $storedCredential,
        ], $assertionResponse);

        if (!is_array($validated)) {
            return null;
        }

        $resolvedUserId = isset($validated['user_id'])
            ? (int) $validated['user_id']
            : (is_array($storedCredential) ? (int) ($storedCredential['user_id'] ?? 0) : 0);

        if ($resolvedUserId <= 0) {
            return null;
        }

        $resolvedCredentialId = isset($validated['credential_id'])
            ? trim((string) $validated['credential_id'])
            : $credentialId;

        if ($resolvedCredentialId !== '') {
            $nextSignCount = max(
                0,
                isset($validated['new_sign_count'])
                    ? (int) $validated['new_sign_count']
                    : (int) ($storedCredential['sign_count'] ?? 0)
            );

            $update = $this->pdo->prepare(
                'UPDATE user_passkey_credentials
                 SET sign_count = :sign_count, last_used_at = UTC_TIMESTAMP()
                 WHERE credential_id = :credential_id AND user_id = :user_id'
            );
            $update->execute([
                'sign_count' => $nextSignCount,
                'credential_id' => $resolvedCredentialId,
                'user_id' => $resolvedUserId,
            ]);
        }

        $context = $this->requestContext->asAuditContext();
        $this->auditLogger->log('auth.passkey.authentication_succeeded', $resolvedUserId, $resolvedUserId, $context);

        return $resolvedUserId;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function findActiveUser(int $userId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, username, real_name
             FROM users
             WHERE id = :id AND deleted_at IS NULL AND status = "active"
             LIMIT 1'
        );
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    /**
     * @return list<string>
     */
    private function listCredentialIdsForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT credential_id FROM user_passkey_credentials WHERE user_id = :user_id'
        );
        $stmt->execute(['user_id' => $userId]);
        $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);

        $ids = [];
        foreach ($rows as $row) {
            if (is_string($row) && $row !== '') {
                $ids[] = $row;
            }
        }

        return $ids;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function findCredentialById(string $credentialId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT user_id, credential_id, public_key, sign_count, transports, aaguid
             FROM user_passkey_credentials
             WHERE credential_id = :credential_id
             LIMIT 1'
        );
        $stmt->execute(['credential_id' => $credentialId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    private function storeChallenge(string $challenge, ?int $userId, string $purpose): bool
    {
        if ($challenge === '' || ($purpose !== 'register' && $purpose !== 'authenticate')) {
            return false;
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO passkey_challenges (challenge_hash, user_id, purpose, expires_at)
               VALUES (:challenge_hash, :user_id, :purpose, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 300 SECOND))'
        );

        return $stmt->execute([
            'challenge_hash' => $this->tokenService->hashToken($challenge),
            'user_id' => $userId,
            'purpose' => $purpose,
        ]);
    }

    private function consumeChallenge(string $challenge, ?int $userId, string $purpose): bool
    {
        if ($challenge === '') {
            return false;
        }

        if ($userId === null) {
            $stmt = $this->pdo->prepare(
                'UPDATE passkey_challenges
                 SET consumed_at = UTC_TIMESTAMP()
                 WHERE challenge_hash = :challenge_hash
                   AND purpose = :purpose
                   AND user_id IS NULL
                   AND consumed_at IS NULL
                   AND expires_at >= UTC_TIMESTAMP()'
            );
            $stmt->execute([
                'challenge_hash' => $this->tokenService->hashToken($challenge),
                'purpose' => $purpose,
            ]);

            return $stmt->rowCount() > 0;
        }

        $stmt = $this->pdo->prepare(
            'UPDATE passkey_challenges
             SET consumed_at = UTC_TIMESTAMP()
             WHERE challenge_hash = :challenge_hash
               AND purpose = :purpose
               AND user_id = :user_id
               AND consumed_at IS NULL
               AND expires_at >= UTC_TIMESTAMP()'
        );
        $stmt->execute([
            'challenge_hash' => $this->tokenService->hashToken($challenge),
            'purpose' => $purpose,
            'user_id' => $userId,
        ]);

        return $stmt->rowCount() > 0;
    }

    private function generateChallenge(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    private function normalizeTransports(mixed $transports): ?string
    {
        if (!is_array($transports)) {
            return null;
        }

        $normalized = [];
        foreach ($transports as $transport) {
            if (!is_string($transport)) {
                continue;
            }

            $trimmed = trim(strtolower($transport));
            if ($trimmed === '') {
                continue;
            }

            $normalized[] = preg_replace('/[^a-z0-9_\-]/', '', $trimmed) ?: '';
        }

        $normalized = array_values(array_filter(array_unique($normalized), static fn (string $value): bool => $value !== ''));

        return $normalized === [] ? null : implode(',', $normalized);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function extractChallenge(array $payload): string
    {
        $challenge = isset($payload['challenge']) ? trim((string) $payload['challenge']) : '';
        if ($challenge !== '') {
            return $challenge;
        }

        if (isset($payload['publicKeyCredential']) && is_array($payload['publicKeyCredential'])) {
            $nestedChallenge = isset($payload['publicKeyCredential']['challenge'])
                ? trim((string) $payload['publicKeyCredential']['challenge'])
                : '';

            if ($nestedChallenge !== '') {
                return $nestedChallenge;
            }
        }

        return '';
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function extractCredentialId(array $payload): string
    {
        $credentialId = isset($payload['credential_id']) ? trim((string) $payload['credential_id']) : '';
        if ($credentialId !== '') {
            return $credentialId;
        }

        $credentialId = isset($payload['id']) ? trim((string) $payload['id']) : '';
        if ($credentialId !== '') {
            return $credentialId;
        }

        if (isset($payload['publicKeyCredential']) && is_array($payload['publicKeyCredential'])) {
            $nestedCredentialId = isset($payload['publicKeyCredential']['id'])
                ? trim((string) $payload['publicKeyCredential']['id'])
                : '';

            if ($nestedCredentialId !== '') {
                return $nestedCredentialId;
            }
        }

        return '';
    }
}
