<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\RecoveryCodeServiceInterface;
use Nexus\DropInUser\Contract\StepUpServiceInterface;
use Nexus\DropInUser\Contract\TotpServiceInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;

final class TotpStepUpService implements StepUpServiceInterface
{
    private const CHALLENGE_KEY = '_nexus_step_up';
    private const CHALLENGE_TTL_SECONDS = 300;

    public function __construct(
        private readonly TotpServiceInterface $totpService,
        private readonly RecoveryCodeServiceInterface $recoveryCodes,
        private readonly PDO $pdo,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly RequestContext $requestContext,
    ) {
    }

    public function startChallenge(int $userId, array $context = []): bool
    {
        if ($userId <= 0) {
            return false;
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $_SESSION[self::CHALLENGE_KEY] = [
            'user_id' => $userId,
            'expires_at' => time() + self::CHALLENGE_TTL_SECONDS,
            'request_id' => (string) ($context['request_id'] ?? ''),
        ];

        return true;
    }

    public function verifyChallenge(int $userId, array $input): bool
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $challenge = $_SESSION[self::CHALLENGE_KEY] ?? null;
        if (!is_array($challenge) || !isset($challenge['user_id'], $challenge['expires_at'])) {
            return false;
        }

        $pendingUserId = (int) $challenge['user_id'];
        if ($pendingUserId <= 0 || (int) $challenge['expires_at'] < time()) {
            unset($_SESSION[self::CHALLENGE_KEY]);
            return false;
        }

        if ($userId > 0 && $pendingUserId !== $userId) {
            return false;
        }

        $otpCode = (string) ($input['otp'] ?? $input['otp_code'] ?? '');
        $recoveryCode = (string) ($input['recovery_code'] ?? '');

        $verified = false;
        if ($otpCode !== '') {
            $verified = $this->totpService->verifyCode($pendingUserId, $otpCode);
        }

        if (!$verified && $recoveryCode !== '') {
            $verified = $this->recoveryCodes->consumeCode($pendingUserId, $recoveryCode);
            if ($verified) {
                $context = $this->requestContext->asAuditContext();
                $this->auditLogger->log('auth.step_up.recovery_code_used', $pendingUserId, $pendingUserId, $context);
            }
        }

        if (!$verified) {
            $context = $this->requestContext->asAuditContext();
            $this->auditLogger->log('auth.step_up.failed', $pendingUserId, $pendingUserId, $context);
            return false;
        }

        session_regenerate_id(true);
        $_SESSION['nexus_user_id'] = $pendingUserId;
        unset($_SESSION[self::CHALLENGE_KEY]);

        $context = $this->requestContext->asAuditContext();
        $sessionStmt = $this->pdo->prepare(
            'INSERT INTO user_sessions (user_id, session_id, ip_address, ua_hash)
             VALUES (:user_id, :session_id, :ip_address, :ua_hash)'
        );
        $sessionStmt->execute([
            'user_id' => $pendingUserId,
            'session_id' => session_id(),
            'ip_address' => $context['source_ip'],
            'ua_hash' => $context['user_agent_hash'],
        ]);

        $updateStmt = $this->pdo->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
        $updateStmt->execute(['id' => $pendingUserId]);

        $this->auditLogger->log('auth.step_up.succeeded', $pendingUserId, $pendingUserId, $context);
        $this->auditLogger->log('auth.login.succeeded', $pendingUserId, $pendingUserId, $context);

        return true;
    }
}
