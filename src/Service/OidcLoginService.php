<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\OidcProviderInterface;
use Nexus\DropInUser\Contract\RoleRepositoryInterface;
use Nexus\DropInUser\Contract\UserRepositoryInterface;
use Nexus\DropInUser\Observability\RequestContext;
use Nexus\DropInUser\Security\PasswordHasher;
use PDO;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class OidcLoginService
{
    private const CHALLENGE_KEY = '_nexus_oidc_google';
    private const CHALLENGE_TTL_SECONDS = 300;

    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly ?OidcProviderInterface $googleProvider,
        private readonly UserRepositoryInterface $users,
        private readonly RoleRepositoryInterface $roles,
        private readonly PasswordHasher $passwordHasher,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
        private readonly PDO $pdo,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function isGoogleConfigured(): bool
    {
        return $this->googleProvider !== null;
    }

    public function startGoogle(): ?string
    {
        if ($this->googleProvider === null) {
            return null;
        }

        $this->startSessionIfNeeded();

        $state = bin2hex(random_bytes(32));
        $nonce = bin2hex(random_bytes(32));
        $_SESSION[self::CHALLENGE_KEY] = [
            'state' => $state,
            'nonce' => $nonce,
            'expires_at' => time() + self::CHALLENGE_TTL_SECONDS,
        ];

        return $this->googleProvider->authorizationUrl($state, $nonce);
    }

    /**
     * @param array<string, mixed> $query
     * @return array{ok: bool, message: string, userId?: int}
     */
    public function handleGoogleCallback(array $query): array
    {
        if ($this->googleProvider === null) {
            return ['ok' => false, 'message' => 'External login is not available.'];
        }

        $this->startSessionIfNeeded();
        $challenge = $_SESSION[self::CHALLENGE_KEY] ?? null;
        unset($_SESSION[self::CHALLENGE_KEY]);

        $state = isset($query['state']) ? (string) $query['state'] : '';
        $code = isset($query['code']) ? (string) $query['code'] : '';
        $error = isset($query['error']) ? (string) $query['error'] : '';

        if ($error !== '' || !$this->isChallengeValid($challenge, $state) || $code === '') {
            return ['ok' => false, 'message' => 'Unable to authenticate with external provider.'];
        }

        try {
            $tokenSet = $this->googleProvider->exchangeCode($code);
            $profile = $this->googleProvider->fetchUserProfile($tokenSet);
        } catch (\Throwable $exception) {
            $this->logger->warning('auth.oidc.google.exchange_failed', [
                'request_id' => $this->requestContext->requestId(),
                'error' => $exception->getMessage(),
            ]);

            return ['ok' => false, 'message' => 'Unable to authenticate with external provider.'];
        }

        $subject = trim((string) ($profile['sub'] ?? ''));
        $email = filter_var((string) ($profile['email'] ?? ''), FILTER_VALIDATE_EMAIL);
        $emailVerified = (bool) ($profile['email_verified'] ?? false);

        if ($subject === '' || !is_string($email) || !$emailVerified) {
            return ['ok' => false, 'message' => 'Unable to authenticate with external provider.'];
        }

        $context = $this->requestContext->asAuditContext();
        $userId = $this->resolveGoogleUser($subject, $email, $profile, $context);
        if ($userId <= 0) {
            return ['ok' => false, 'message' => 'Unable to authenticate with external provider.'];
        }

        $this->establishSession($userId, $context);
        $this->auditLogger->log('auth.oidc.google.login_succeeded', $userId, $userId, $context);

        return ['ok' => true, 'message' => 'Login successful.', 'userId' => $userId];
    }

    /**
     * @param array<string, mixed>|mixed $challenge
     */
    private function isChallengeValid(mixed $challenge, string $state): bool
    {
        if (!is_array($challenge) || !isset($challenge['state'], $challenge['expires_at'])) {
            return false;
        }

        $expectedState = (string) $challenge['state'];
        $expiresAt = (int) $challenge['expires_at'];

        if ($expiresAt < time()) {
            return false;
        }

        if ($state === '' || $expectedState === '') {
            return false;
        }

        return hash_equals($expectedState, $state);
    }

    /**
     * @param array<string, mixed> $profile
     * @param array<string, mixed> $context
     */
    private function resolveGoogleUser(string $subject, string $email, array $profile, array $context): int
    {
        try {
            $this->pdo->beginTransaction();

            $userId = $this->findUserIdByIdentity('google', $subject);
            if ($userId <= 0) {
                $userId = $this->findActiveUserIdByEmail($email);
            }

            if ($userId <= 0) {
                $username = $this->generateUsernameFromEmail($email);
                $realName = $this->normalizeRealName((string) ($profile['name'] ?? ''));
                $passwordHash = $this->passwordHasher->hash(bin2hex(random_bytes(24)));
                $created = $this->users->create($username, $email, $realName, $passwordHash);
                $userId = (int) ($created['id'] ?? 0);
                if ($userId <= 0) {
                    throw new \RuntimeException('Unable to create user from OIDC profile.');
                }

                $this->roles->assignRole($userId, 'user');
                $this->auditLogger->log('auth.oidc.google.user_created', $userId, $userId, $context);
            }

            $this->users->markEmailVerified($userId);
            $this->upsertIdentity($userId, 'google', $subject, $email);

            if ($this->pdo->inTransaction()) {
                $this->pdo->commit();
            }

            return $userId;
        } catch (\Throwable $exception) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }

            $this->logger->warning('auth.oidc.google.resolve_failed', [
                'request_id' => $context['request_id'] ?? null,
                'error' => $exception->getMessage(),
            ]);

            return 0;
        }
    }

    private function findUserIdByIdentity(string $provider, string $subject): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT user_id
             FROM user_oidc_identities
             WHERE provider = :provider AND subject = :subject
             LIMIT 1'
        );
        $stmt->execute([
            'provider' => $provider,
            'subject' => $subject,
        ]);

        $value = $stmt->fetchColumn();

        return is_numeric($value) ? (int) $value : 0;
    }

    private function findActiveUserIdByEmail(string $email): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT id
             FROM users
             WHERE email = :email AND deleted_at IS NULL
             LIMIT 1'
        );
        $stmt->execute(['email' => $email]);

        $value = $stmt->fetchColumn();

        return is_numeric($value) ? (int) $value : 0;
    }

    private function upsertIdentity(int $userId, string $provider, string $subject, string $email): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO user_oidc_identities (user_id, provider, subject, email)
             VALUES (:user_id, :provider, :subject, :email)
             ON DUPLICATE KEY UPDATE
               user_id = VALUES(user_id),
               email = VALUES(email),
               updated_at = CURRENT_TIMESTAMP'
        );
        $stmt->execute([
            'user_id' => $userId,
            'provider' => $provider,
            'subject' => $subject,
            'email' => $email,
        ]);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function establishSession(int $userId, array $context): void
    {
        $this->startSessionIfNeeded();
        session_regenerate_id(true);
        $_SESSION['nexus_user_id'] = $userId;

        $sessionStmt = $this->pdo->prepare(
            'INSERT INTO user_sessions (user_id, session_id, ip_address, ua_hash)
             VALUES (:user_id, :session_id, :ip_address, :ua_hash)'
        );
        $sessionStmt->execute([
            'user_id' => $userId,
            'session_id' => session_id(),
            'ip_address' => $context['source_ip'] ?? null,
            'ua_hash' => $context['user_agent_hash'] ?? null,
        ]);

        $updateStmt = $this->pdo->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
        $updateStmt->execute(['id' => $userId]);
    }

    private function startSessionIfNeeded(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    }

    private function generateUsernameFromEmail(string $email): string
    {
        $local = explode('@', strtolower($email), 2)[0] ?? 'user';
        $base = preg_replace('/[^a-z0-9_]+/', '_', $local) ?? 'user';
        $base = trim($base, '_');
        if ($base === '') {
            $base = 'user';
        }
        if (strlen($base) < 3) {
            $base .= '_user';
        }

        $candidate = substr($base, 0, 40);
        for ($attempt = 0; $attempt < 20; $attempt++) {
            $username = $attempt === 0 ? $candidate : substr($candidate, 0, 40) . '_' . random_int(1000, 9999);
            if (!$this->usernameExists($username)) {
                return $username;
            }
        }

        return 'user_' . bin2hex(random_bytes(4));
    }

    private function usernameExists(string $username): bool
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM users WHERE username = :username LIMIT 1');
        $stmt->execute(['username' => $username]);

        return (bool) $stmt->fetchColumn();
    }

    private function normalizeRealName(string $realName): string
    {
        $clean = trim($realName);
        if ($clean === '') {
            return 'Google User';
        }

        if (mb_strlen($clean) < 2) {
            return 'Google User';
        }

        if (mb_strlen($clean) > 120) {
            return mb_substr($clean, 0, 120);
        }

        return $clean;
    }
}
