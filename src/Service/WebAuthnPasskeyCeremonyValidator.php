<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;
use Nexus\DropInUser\Contract\PasskeyCeremonyValidatorInterface;

final class WebAuthnPasskeyCeremonyValidator implements PasskeyCeremonyValidatorInterface
{
    public function __construct(
        private readonly string $rpId,
        private readonly string $rpOrigin,
        private readonly string $rpName = 'Nexus User Module',
    ) {
    }

    public function createRegistrationOptions(array $context): array
    {
        $challenge = isset($context['challenge']) ? (string) $context['challenge'] : '';
        $user = isset($context['user']) && is_array($context['user']) ? $context['user'] : [];
        $userId = isset($user['id']) ? (int) $user['id'] : 0;

        if ($challenge === '' || $userId <= 0) {
            return [];
        }

        $username = trim((string) ($user['username'] ?? 'user_' . $userId));
        $displayName = trim((string) ($user['real_name'] ?? $username));
        $userHandle = $this->userHandleForUserId($userId);

        $excludeCredentialDescriptors = [];
        foreach (($context['exclude_credential_ids'] ?? []) as $credentialId) {
            if (!is_string($credentialId) || trim($credentialId) === '') {
                continue;
            }

            $excludeCredentialDescriptors[] = PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $this->base64UrlDecode($credentialId),
            );
        }

        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($this->rpName, $this->rpId),
            PublicKeyCredentialUserEntity::create($username, $userHandle, $displayName),
            $this->base64UrlDecode($challenge),
            [
                PublicKeyCredentialParameters::createPk(-7),
                PublicKeyCredentialParameters::createPk(-257),
            ],
            AuthenticatorSelectionCriteria::create(
                null,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $excludeCredentialDescriptors,
            60000,
        );

        return $this->normalizeCreationOptions($options);
    }

    public function validateRegistrationResponse(array $context, array $attestationResponse): ?array
    {
        $challenge = isset($context['challenge']) ? (string) $context['challenge'] : '';
        $userId = isset($context['user_id']) ? (int) $context['user_id'] : 0;
        $user = isset($context['user']) && is_array($context['user']) ? $context['user'] : [];
        $username = trim((string) ($user['username'] ?? 'user_' . $userId));
        $displayName = trim((string) ($user['real_name'] ?? $username));

        if ($challenge === '' || $userId <= 0) {
            return null;
        }

        $publicKeyCredentialArray = $this->extractPublicKeyCredential($attestationResponse);
        if ($publicKeyCredentialArray === null) {
            return null;
        }

        $credential = $this->loadPublicKeyCredential($publicKeyCredentialArray);
        if (!$credential instanceof PublicKeyCredential || !$credential->response instanceof AuthenticatorAttestationResponse) {
            return null;
        }

        $creationOptions = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($this->rpName, $this->rpId),
            PublicKeyCredentialUserEntity::create($username, $this->userHandleForUserId($userId), $displayName),
            $this->base64UrlDecode($challenge),
            [
                PublicKeyCredentialParameters::createPk(-7),
                PublicKeyCredentialParameters::createPk(-257),
            ],
            AuthenticatorSelectionCriteria::create(
                null,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            [],
            60000,
        );

        $attestationStatementSupportManager = new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
        ]);
        $validator = new AuthenticatorAttestationResponseValidator($attestationStatementSupportManager);

        try {
            $source = $validator->check(
                $credential->response,
                $creationOptions,
                parse_url($this->rpOrigin, PHP_URL_HOST) ?: $this->rpId,
            );
        } catch (\Throwable) {
            return null;
        }

        $transports = [];
        foreach ($source->transports as $transport) {
            if (!is_string($transport) || trim($transport) === '') {
                continue;
            }
            $transports[] = trim($transport);
        }

        return [
            'credential_id' => $this->base64UrlEncode($source->publicKeyCredentialId),
            'public_key' => $this->base64UrlEncode($source->credentialPublicKey),
            'sign_count' => $source->counter,
            'transports' => $transports,
            'aaguid' => $source->aaguid->toRfc4122(),
            'user_handle' => $this->base64UrlEncode($source->userHandle),
        ];
    }
    public function createAuthenticationOptions(array $context): array
    {
        $challenge = isset($context['challenge']) ? (string) $context['challenge'] : '';
        if ($challenge === '') {
            return [];
        }

        $allowCredentialDescriptors = [];
        foreach (($context['allowed_credential_ids'] ?? []) as $credentialId) {
            if (!is_string($credentialId) || trim($credentialId) === '') {
                continue;
            }

            $allowCredentialDescriptors[] = PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $this->base64UrlDecode($credentialId),
            );
        }

        $options = PublicKeyCredentialRequestOptions::create(
            $this->base64UrlDecode($challenge),
            $this->rpId,
            $allowCredentialDescriptors,
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            60000,
        );

        return $this->normalizeRequestOptions($options);
    }

    public function validateAuthenticationResponse(array $context, array $assertionResponse): ?array
    {
        $challenge = isset($context['challenge']) ? (string) $context['challenge'] : '';
        $storedCredential = isset($context['stored_credential']) && is_array($context['stored_credential'])
            ? $context['stored_credential']
            : null;

        if ($challenge === '' || !is_array($storedCredential)) {
            return null;
        }

        $credentialId = isset($storedCredential['credential_id']) ? (string) $storedCredential['credential_id'] : '';
        $credentialPublicKey = isset($storedCredential['public_key']) ? (string) $storedCredential['public_key'] : '';
        $userId = isset($storedCredential['user_id']) ? (int) $storedCredential['user_id'] : 0;
        $signCount = isset($storedCredential['sign_count']) ? (int) $storedCredential['sign_count'] : 0;
        if ($credentialId === '' || $credentialPublicKey === '' || $userId <= 0) {
            return null;
        }

        $publicKeyCredentialArray = $this->extractPublicKeyCredential($assertionResponse);
        if ($publicKeyCredentialArray === null) {
            return null;
        }

        $credential = $this->loadPublicKeyCredential($publicKeyCredentialArray);
        if (!$credential instanceof PublicKeyCredential || !$credential->response instanceof AuthenticatorAssertionResponse) {
            return null;
        }

        $requestOptions = PublicKeyCredentialRequestOptions::create(
            $this->base64UrlDecode($challenge),
            $this->rpId,
            [
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    $this->base64UrlDecode($credentialId),
                ),
            ],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            60000,
        );

        $source = PublicKeyCredentialSource::create(
            $this->base64UrlDecode($credentialId),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $this->explodeTransports((string) ($storedCredential['transports'] ?? '')),
            'none',
            EmptyTrustPath::create(),
            $this->normalizeAaguid((string) ($storedCredential['aaguid'] ?? '')),
            $this->base64UrlDecode($credentialPublicKey),
            $this->userHandleForUserId($userId),
            max(0, $signCount),
        );

        $validator = new AuthenticatorAssertionResponseValidator();
        try {
            $validatedSource = $validator->check(
                $source,
                $credential->response,
                $requestOptions,
                parse_url($this->rpOrigin, PHP_URL_HOST) ?: $this->rpId,
                $source->userHandle,
            );
        } catch (\Throwable) {
            return null;
        }

        return [
            'user_id' => $userId,
            'credential_id' => $this->base64UrlEncode($validatedSource->publicKeyCredentialId),
            'new_sign_count' => max(0, (int) $validatedSource->counter),
        ];
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>|null
     */
    private function extractPublicKeyCredential(array $payload): ?array
    {
        if (isset($payload['publicKeyCredential']) && is_array($payload['publicKeyCredential'])) {
            return $payload['publicKeyCredential'];
        }

        if (isset($payload['id'], $payload['rawId'], $payload['type'], $payload['response']) && is_array($payload['response'])) {
            return $payload;
        }

        return null;
    }

    private function loadPublicKeyCredential(array $credentialPayload): ?PublicKeyCredential
    {
        $attestationStatementSupportManager = new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
        ]);
        $attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager);
        $loader = new PublicKeyCredentialLoader($attestationObjectLoader);

        try {
            return $loader->loadArray($credentialPayload);
        } catch (\Throwable) {
            return null;
        }
    }
    private function normalizeCreationOptions(PublicKeyCredentialCreationOptions $options): array
    {
        $result = [
            'rp' => [
                'name' => $options->rp->name,
                'id' => $options->rp->id,
            ],
            'user' => [
                'name' => $options->user->name,
                'displayName' => $options->user->displayName,
                'id' => $this->base64UrlEncode($options->user->id),
            ],
            'challenge' => $this->base64UrlEncode($options->challenge),
            'pubKeyCredParams' => array_map(
                static fn (PublicKeyCredentialParameters $parameter): array => [
                    'type' => $parameter->type,
                    'alg' => $parameter->alg,
                ],
                $options->pubKeyCredParams,
            ),
            'timeout' => $options->timeout,
            'attestation' => $options->attestation,
        ];

        if ($options->authenticatorSelection !== null) {
            $result['authenticatorSelection'] = [
                'authenticatorAttachment' => $options->authenticatorSelection->authenticatorAttachment,
                'residentKey' => $options->authenticatorSelection->residentKey,
                'requireResidentKey' => $options->authenticatorSelection->requireResidentKey,
                'userVerification' => $options->authenticatorSelection->userVerification,
            ];
        }

        if ($options->excludeCredentials !== []) {
            $result['excludeCredentials'] = array_map(
                fn (PublicKeyCredentialDescriptor $descriptor): array => [
                    'type' => $descriptor->type,
                    'id' => $this->base64UrlEncode($descriptor->id),
                    'transports' => $descriptor->transports,
                ],
                $options->excludeCredentials,
            );
        }

        return $result;
    }

    private function normalizeRequestOptions(PublicKeyCredentialRequestOptions $options): array
    {
        $result = [
            'challenge' => $this->base64UrlEncode($options->challenge),
            'rpId' => $options->rpId,
            'timeout' => $options->timeout,
            'userVerification' => $options->userVerification,
        ];

        if ($options->allowCredentials !== []) {
            $result['allowCredentials'] = array_map(
                fn (PublicKeyCredentialDescriptor $descriptor): array => [
                    'type' => $descriptor->type,
                    'id' => $this->base64UrlEncode($descriptor->id),
                    'transports' => $descriptor->transports,
                ],
                $options->allowCredentials,
            );
        }

        return $result;
    }

    private function base64UrlEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $encoded): string
    {
        $remainder = strlen($encoded) % 4;
        if ($remainder > 0) {
            $encoded .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        return is_string($decoded) ? $decoded : '';
    }

    /**
     * @return list<string>
     */
    private function explodeTransports(string $csv): array
    {
        if (trim($csv) === '') {
            return [];
        }

        $result = [];
        foreach (explode(',', $csv) as $transport) {
            $trimmed = trim($transport);
            if ($trimmed === '') {
                continue;
            }
            $result[] = $trimmed;
        }

        return $result;
    }

    private function normalizeAaguid(string $aaguid): Uuid
    {
        try {
            return Uuid::fromString($aaguid);
        } catch (\Throwable) {
            return Uuid::fromString('00000000-0000-0000-0000-000000000000');
        }
    }

    private function userHandleForUserId(int $userId): string
    {
        return 'uid:' . $userId;
    }
}
