<?php

declare(strict_types=1);

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\EmailVerificationServiceInterface;
use Nexus\DropInUser\Contract\EventDispatcherInterface;
use Nexus\DropInUser\Contract\MailerInterface;
use Nexus\DropInUser\Contract\ProfileFieldPolicyInterface;
use Nexus\DropInUser\Contract\RememberMeServiceInterface;
use Nexus\DropInUser\Contract\RoleRepositoryInterface;
use Nexus\DropInUser\Contract\RiskEngineInterface;
use Nexus\DropInUser\Contract\StepUpServiceInterface;
use Nexus\DropInUser\Contract\UserProfileFieldRepositoryInterface;
use Nexus\DropInUser\Contract\UserRepositoryInterface;
use Nexus\DropInUser\Mail\ConfigurableEmailTemplateProvider;
use Nexus\DropInUser\Observability\RequestContext;
use Nexus\DropInUser\RateLimit\RateLimiter;
use Nexus\DropInUser\Risk\RiskDecision;
use Nexus\DropInUser\Security\PasswordHasher;
use Nexus\DropInUser\Security\TokenService;
use Nexus\DropInUser\Service\AuthService;

require __DIR__ . '/../../vendor/autoload.php';

$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_USER_AGENT'] = 'nexus-test-agent';

$mailer = new class () implements MailerInterface {
    /** @var list<array{to:string,subject:string,text:string}> */
    public array $sent = [];

    public function send(string $toEmail, string $subject, string $textBody): void
    {
        $this->sent[] = [
            'to' => $toEmail,
            'subject' => $subject,
            'text' => $textBody,
        ];
    }
};

$users = new class () implements UserRepositoryInterface {
    /** @var array<string,mixed>|null */
    private ?array $createdUser = null;

    public function findByEmailOrUsername(string $identifier): ?array
    {
        if ($this->createdUser === null) {
            return null;
        }

        if (($this->createdUser['username'] ?? null) === $identifier || ($this->createdUser['email'] ?? null) === $identifier) {
            return $this->createdUser;
        }

        return null;
    }

    public function create(string $username, string $email, string $realName, string $passwordHash): array
    {
        $this->createdUser = [
            'id' => 101,
            'username' => $username,
            'email' => $email,
            'real_name' => $realName,
            'password_hash' => $passwordHash,
            'status' => 'active',
        ];

        return $this->createdUser;
    }

    public function markEmailVerified(int $userId): void
    {
    }
};

$profileFields = new class () implements UserProfileFieldRepositoryInterface {
    public function getFields(int $userId): array
    {
        return [];
    }

    public function upsertFields(int $userId, array $fields): void
    {
    }

    public function deleteField(int $userId, string $fieldKey): void
    {
    }
};

$profilePolicy = new class () implements ProfileFieldPolicyInterface {
    public function validateForRegistration(array $fields): array
    {
        return ['ok' => true, 'fields' => $fields, 'errors' => []];
    }

    public function validateForProfileUpdate(array $fields): array
    {
        return ['ok' => true, 'fields' => $fields, 'errors' => []];
    }

    public function filterVisibleForUser(array $fields): array
    {
        return $fields;
    }

    public function userFieldDefinitions(): array
    {
        return [];
    }
};

$rateLimiter = new class () implements RateLimiter {
    public function allow(string $bucket, int $limit, int $windowSeconds): bool
    {
        return true;
    }
};

$emailVerification = new class () implements EmailVerificationServiceInterface {
    public function createForUser(int $userId): string
    {
        return 'verification-token-123';
    }

    public function consume(string $token): bool
    {
        return true;
    }
};

$audit = new class () implements AuditLoggerInterface {
    public function log(string $eventType, ?int $actorUserId, ?int $targetUserId, array $context = []): void
    {
    }
};

$rememberMe = new class () implements RememberMeServiceInterface {
    public function issue(int $userId, int $ttlDays = 30): string
    {
        return 'remember-token';
    }

    public function consumeAndRotate(string $cookieValue): ?array
    {
        return null;
    }

    public function revokeBySelector(string $selector): void
    {
    }
};

$roles = new class () implements RoleRepositoryInterface {
    public function hasRole(int $userId, string $roleName): bool
    {
        return false;
    }

    public function can(int $userId, string $permission): bool
    {
        return false;
    }

    public function assignRole(int $userId, string $roleName): bool
    {
        return true;
    }

    public function revokeRole(int $userId, string $roleName): bool
    {
        return true;
    }

    public function rolesForUser(int $userId): array
    {
        return [];
    }
};

$riskEngine = new class () implements RiskEngineInterface {
    public function assess(?array $lastSession, string $currentIp, string $currentUserAgentHash, string $ipBindingMode, bool $bindUserAgent): string
    {
        return RiskDecision::ALLOW;
    }
};

$stepUp = new class () implements StepUpServiceInterface {
    public function startChallenge(int $userId, array $context = []): bool
    {
        return true;
    }

    public function verifyChallenge(int $userId, array $input): bool
    {
        return true;
    }
};

$events = new class () implements EventDispatcherInterface {
    public function dispatch(string $eventName, array $payload = []): void
    {
    }
};

$templates = new ConfigurableEmailTemplateProvider([
    'verify_email' => [
        'subject' => 'Verify your email',
        'text' => 'Token: {{token}}',
    ],
    'admin_new_user_registered' => [
        'subject' => 'New user registration',
        'text' => 'New user: {{username}} <{{email}}>',
    ],
]);

$auth = new AuthService(
    users: $users,
    passwordHasher: new PasswordHasher(),
    auditLogger: $audit,
    profileFields: $profileFields,
    profileFieldPolicy: $profilePolicy,
    rateLimiter: $rateLimiter,
    emailVerification: $emailVerification,
    mailer: $mailer,
    emailTemplates: $templates,
    rememberMeService: $rememberMe,
    roles: $roles,
    riskEngine: $riskEngine,
    stepUpService: $stepUp,
    events: $events,
    ipBindingMode: 'off',
    bindUserAgent: false,
    requestContext: new RequestContext(new TokenService()),
    adminRegistrationNotificationRecipients: [
        'admin1@example.com',
        'invalid-recipient',
        'admin2@example.com',
    ],
    pdo: new PDO('sqlite::memory:'),
);

$result = $auth->register('newuser', 'newuser@example.com', 'New User', 'LongPassword123!', []);
if (($result['ok'] ?? false) !== true) {
    throw new RuntimeException('Expected registration to succeed.');
}

if (count($mailer->sent) !== 3) {
    throw new RuntimeException('Expected 3 emails (1 user + 2 admin), got ' . count($mailer->sent));
}

if ($mailer->sent[0]['to'] !== 'newuser@example.com') {
    throw new RuntimeException('Expected first email to be sent to registering user.');
}

if ($mailer->sent[1]['to'] !== 'admin1@example.com' || $mailer->sent[2]['to'] !== 'admin2@example.com') {
    throw new RuntimeException('Expected admin notifications to be sent to configured admin recipients.');
}

if ($mailer->sent[1]['subject'] !== 'New user registration') {
    throw new RuntimeException('Expected admin notification subject to use admin template.');
}

if (!str_contains($mailer->sent[1]['text'], 'newuser <newuser@example.com>')) {
    throw new RuntimeException('Expected admin notification body to include user details.');
}

echo "auth_service_admin_registration_notification_test: ok\n";
