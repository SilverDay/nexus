<?php
declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\AuthServiceInterface;
use Nexus\DropInUser\Contract\EmailTemplateProviderInterface;
use Nexus\DropInUser\Contract\EmailVerificationServiceInterface;
use Nexus\DropInUser\Contract\EventDispatcherInterface;
use Nexus\DropInUser\Contract\MailerInterface;
use Nexus\DropInUser\Contract\ProfileFieldPolicyInterface;
use Nexus\DropInUser\Contract\RememberMeServiceInterface;
use Nexus\DropInUser\Contract\RoleRepositoryInterface;
use Nexus\DropInUser\Contract\RiskEngineInterface;
use Nexus\DropInUser\Contract\StepUpServiceInterface;
use Nexus\DropInUser\Contract\UserRepositoryInterface;
use Nexus\DropInUser\Contract\UserProfileFieldRepositoryInterface;
use Nexus\DropInUser\Observability\RequestContext;
use Nexus\DropInUser\RateLimit\RateLimiter;
use Nexus\DropInUser\Risk\RiskDecision;
use Nexus\DropInUser\Security\PasswordHasher;
use PDO;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class AuthService implements AuthServiceInterface
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly UserRepositoryInterface $users,
        private readonly PasswordHasher $passwordHasher,
        private readonly AuditLoggerInterface $auditLogger,
        private readonly UserProfileFieldRepositoryInterface $profileFields,
        private readonly ProfileFieldPolicyInterface $profileFieldPolicy,
        private readonly RateLimiter $rateLimiter,
        private readonly EmailVerificationServiceInterface $emailVerification,
        private readonly MailerInterface $mailer,
        private readonly EmailTemplateProviderInterface $emailTemplates,
        private readonly RememberMeServiceInterface $rememberMeService,
        private readonly RoleRepositoryInterface $roles,
        private readonly RiskEngineInterface $riskEngine,
        private readonly StepUpServiceInterface $stepUpService,
        private readonly EventDispatcherInterface $events,
        private readonly string $ipBindingMode,
        private readonly bool $bindUserAgent,
        private readonly RequestContext $requestContext,
        private readonly PDO $pdo,
        private readonly ?string $verificationLinkTemplate = null,
        /** @var list<string> */
        private readonly array $adminRegistrationNotificationRecipients = [],
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function register(string $username, string $email, string $realName, string $password, array $profileFields = []): array
    {
        $context = $this->requestContext->asAuditContext();

        if (!$this->rateLimiter->allow('register:ip:' . $context['source_ip'], 10, 300)) {
            $this->logger->warning('auth.register.rate_limited', ['request_id' => $context['request_id']]);
            return ['ok' => false, 'message' => 'Unable to process request.'];
        }

        if (!$this->isValidRegistration($username, $email, $realName, $password)) {
            return ['ok' => false, 'message' => 'Unable to process request.'];
        }

        if ($this->users->findByEmailOrUsername($username) !== null || $this->users->findByEmailOrUsername($email) !== null) {
            return ['ok' => false, 'message' => 'Unable to process request.'];
        }

        $validatedProfile = $this->profileFieldPolicy->validateForRegistration(
            $this->normalizeProfileFields($profileFields)
        );
        if (!$validatedProfile['ok']) {
            $this->logger->notice('auth.register.profile_fields_invalid', ['request_id' => $context['request_id']]);
            return ['ok' => false, 'message' => 'Unable to process request.'];
        }

        $passwordHash = $this->passwordHasher->hash($password);
        $user = $this->users->create($username, $email, $realName, $passwordHash);
        $this->roles->assignRole((int) $user['id'], 'user');
        $this->profileFields->upsertFields((int) $user['id'], $validatedProfile['fields']);

        $verificationToken = $this->emailVerification->createForUser((int) $user['id']);
        $verificationMail = $this->emailTemplates->render('verify_email', [
            'token' => $verificationToken,
            'verify_link' => $this->buildVerificationLink($verificationToken),
            'username' => (string) $user['username'],
            'email' => (string) $user['email'],
            'real_name' => (string) $user['real_name'],
        ]);
        $this->mailer->send(
            (string) $user['email'],
            $verificationMail['subject'],
            $verificationMail['text']
        );
        $this->notifyAdminsOfNewRegistration($user, $context);

        $this->auditLogger->log('user.registered', (int) $user['id'], (int) $user['id'], $context);
        $this->events->dispatch('user.registered', [
            'user_id' => (int) $user['id'],
            'request_id' => $context['request_id'],
        ]);
        $this->logger->info('auth.register.succeeded', [
            'user_id' => (int) $user['id'],
            'request_id' => $context['request_id'],
        ]);

        return ['ok' => true, 'message' => 'If registration is successful, a verification email is sent.'];
    }

    /**
     * @param array<string,mixed> $user
     * @param array<string,mixed> $context
     */
    private function notifyAdminsOfNewRegistration(array $user, array $context): void
    {
        foreach ($this->adminRegistrationNotificationRecipients as $recipient) {
            if (!filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
                continue;
            }

            try {
                $mail = $this->emailTemplates->render('admin_new_user_registered', [
                    'user_id' => (string) ($user['id'] ?? ''),
                    'username' => (string) ($user['username'] ?? ''),
                    'email' => (string) ($user['email'] ?? ''),
                    'real_name' => (string) ($user['real_name'] ?? ''),
                    'request_id' => (string) ($context['request_id'] ?? ''),
                    'source_ip' => (string) ($context['source_ip'] ?? ''),
                ]);

                $this->mailer->send($recipient, $mail['subject'], $mail['text']);
            } catch (\Throwable $exception) {
                $this->logger->warning('auth.register.admin_notification_failed', [
                    'request_id' => $context['request_id'] ?? null,
                    'target_email' => $recipient,
                ]);
            }
        }
    }

    private function buildVerificationLink(string $token): string
    {
        $template = $this->verificationLinkTemplate;
        if (!is_string($template) || trim($template) === '') {
            return '';
        }

        $trimmedTemplate = trim($template);
        if (str_contains($trimmedTemplate, '{{token}}')) {
            return str_replace('{{token}}', rawurlencode($token), $trimmedTemplate);
        }

        $separator = str_contains($trimmedTemplate, '?') ? '&' : '?';

        return $trimmedTemplate . $separator . 'token=' . rawurlencode($token);
    }

    public function login(string $identifier, string $password, bool $rememberMe = false): array
    {
        $context = $this->requestContext->asAuditContext();
        $ipBucket = 'login:ip:' . $context['source_ip'];
        $idBucket = 'login:id:' . strtolower(trim($identifier));

        if (!$this->rateLimiter->allow($ipBucket, 20, 300) || !$this->rateLimiter->allow($idBucket, 8, 300)) {
            $this->logger->warning('auth.login.rate_limited', ['request_id' => $context['request_id']]);
            return ['ok' => false, 'message' => 'Invalid credentials.'];
        }

        $user = $this->users->findByEmailOrUsername($identifier);
        if ($user === null || !isset($user['password_hash']) || !$this->passwordHasher->verify($password, (string) $user['password_hash'])) {
            $this->auditLogger->log('auth.login.failed', null, $user['id'] ?? null, $context);
            $this->logger->notice('auth.login.failed', ['request_id' => $context['request_id']]);
            return ['ok' => false, 'message' => 'Invalid credentials.'];
        }

        if (($user['status'] ?? 'active') !== 'active') {
            return ['ok' => false, 'message' => 'Invalid credentials.'];
        }

        $lastSession = $this->fetchLastUserSession((int) $user['id']);
        $riskDecision = $this->riskEngine->assess(
            $lastSession,
            $context['source_ip'],
            $context['user_agent_hash'],
            $this->ipBindingMode,
            $this->bindUserAgent,
        );

        if ($riskDecision === RiskDecision::DENY) {
            $this->auditLogger->log('auth.login.denied_risk', (int) $user['id'], (int) $user['id'], $context);
            $this->events->dispatch('auth.login.denied_risk', [
                'user_id' => (int) $user['id'],
                'request_id' => $context['request_id'],
            ]);
            $this->logger->warning('auth.login.denied_risk', ['user_id' => (int) $user['id'], 'request_id' => $context['request_id']]);
            return ['ok' => false, 'message' => 'Invalid credentials.'];
        }

        if ($riskDecision === RiskDecision::REQUIRE_STEP_UP) {
            $challengeStarted = $this->stepUpService->startChallenge((int) $user['id'], $context);
            if (!$challengeStarted) {
                $this->auditLogger->log('auth.login.step_up_unavailable', (int) $user['id'], (int) $user['id'], $context);
                $this->events->dispatch('auth.login.step_up_unavailable', [
                    'user_id' => (int) $user['id'],
                    'request_id' => $context['request_id'],
                ]);
                $this->logger->warning('auth.login.step_up_unavailable', ['user_id' => (int) $user['id'], 'request_id' => $context['request_id']]);

                return ['ok' => false, 'message' => 'Invalid credentials.'];
            }

            $this->auditLogger->log('auth.login.require_step_up', (int) $user['id'], (int) $user['id'], $context);
            $this->events->dispatch('auth.login.require_step_up', [
                'user_id' => (int) $user['id'],
                'request_id' => $context['request_id'],
            ]);
            $this->logger->notice('auth.login.require_step_up', ['user_id' => (int) $user['id'], 'request_id' => $context['request_id']]);
            return ['ok' => false, 'message' => 'Additional verification required.'];
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        session_regenerate_id(true);
        $_SESSION['nexus_user_id'] = (int) $user['id'];

        $sessionStmt = $this->pdo->prepare(
            'INSERT INTO user_sessions (user_id, session_id, ip_address, ua_hash)
             VALUES (:user_id, :session_id, :ip_address, :ua_hash)'
        );
        $sessionStmt->execute([
            'user_id' => $user['id'],
            'session_id' => session_id(),
            'ip_address' => $context['source_ip'],
            'ua_hash' => $context['user_agent_hash'],
        ]);

        $updateStmt = $this->pdo->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
        $updateStmt->execute(['id' => $user['id']]);

        $this->auditLogger->log('auth.login.succeeded', (int) $user['id'], (int) $user['id'], $context);
        $this->events->dispatch('auth.login.succeeded', [
            'user_id' => (int) $user['id'],
            'request_id' => $context['request_id'],
        ]);
        $this->logger->info('auth.login.succeeded', [
            'user_id' => (int) $user['id'],
            'request_id' => $context['request_id'],
        ]);

        $response = ['ok' => true, 'message' => 'Login successful.', 'userId' => (int) $user['id']];

        if ($rememberMe) {
            $response['rememberMeToken'] = $this->rememberMeService->issue((int) $user['id']);
        }

        return $response;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function fetchLastUserSession(int $userId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT ip_address, ua_hash
             FROM user_sessions
             WHERE user_id = :user_id AND revoked_at IS NULL
             ORDER BY last_seen_at DESC
             LIMIT 1'
        );
        $stmt->execute(['user_id' => $userId]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($session) ? $session : null;
    }

    /**
     * @param array<string, mixed> $profileFields
     * @return array<string, string>
     */
    private function normalizeProfileFields(array $profileFields): array
    {
        $normalized = [];
        foreach ($profileFields as $key => $value) {
            if (!is_string($key) || !is_scalar($value)) {
                continue;
            }

            $normalized[$key] = (string) $value;
        }

        return $normalized;
    }

    private function isValidRegistration(string $username, string $email, string $realName, string $password): bool
    {
        if (mb_strlen($username) < 3 || mb_strlen($username) > 50) {
            return false;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }

        if (mb_strlen(trim($realName)) < 2 || mb_strlen($realName) > 120) {
            return false;
        }

        return mb_strlen($password) >= 12;
    }

}
