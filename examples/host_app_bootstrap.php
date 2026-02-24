<?php

declare(strict_types=1);

use Nexus\DropInUser\Audit\PdoAuditLogger;
use Nexus\DropInUser\Config\ModuleConfig;
use Nexus\DropInUser\Controller\AuthJsonController;
use Nexus\DropInUser\Event\NullEventDispatcher;
use Nexus\DropInUser\Mail\ConfigurableEmailTemplateProvider;
use Nexus\DropInUser\Mail\FileEmailTemplateProvider;
use Nexus\DropInUser\Mail\MailerFactory;
use Nexus\DropInUser\Observability\RequestContext;
use Nexus\DropInUser\Profile\DatabaseProfileFieldPolicy;
use Nexus\DropInUser\RateLimit\PdoRateLimiter;
use Nexus\DropInUser\Repository\PdoProfileFieldDefinitionRepository;
use Nexus\DropInUser\Repository\PdoRoleRepository;
use Nexus\DropInUser\Repository\PdoUserProfileFieldRepository;
use Nexus\DropInUser\Repository\PdoUserRepository;
use Nexus\DropInUser\Risk\BasicRiskEngine;
use Nexus\DropInUser\Security\PasswordHasher;
use Nexus\DropInUser\Security\TokenService;
use Nexus\DropInUser\Service\AuthService;
use Nexus\DropInUser\Service\EmailVerificationService;
use Nexus\DropInUser\Service\NullStepUpService;
use Nexus\DropInUser\Service\PasswordResetService;
use Nexus\DropInUser\Service\RememberMeService;
use Psr\Log\NullLogger;

require __DIR__ . '/../vendor/autoload.php';

function bootstrapNexusModule(\PDO $sharedPdo, array $options = []): array
{
    $tokenService = new TokenService();
    $requestContext = new RequestContext($tokenService);
    $logger = new NullLogger();

    $config = new ModuleConfig(
        dbDsn: '',
        dbUser: '',
        dbPassword: '',
        fromEmail: (string) ($options['from_email'] ?? 'noreply@example.com'),
        fromName: (string) ($options['from_name'] ?? 'Nexus User Module'),
        secureCookies: (bool) ($options['secure_cookies'] ?? true),
        sameSite: (string) ($options['same_site'] ?? 'Lax'),
        ipBindingMode: (string) ($options['ip_binding_mode'] ?? 'subnet'),
        bindUserAgent: (bool) ($options['bind_user_agent'] ?? true),
        exposeDebugTokens: (bool) ($options['expose_debug_tokens'] ?? false),
    );

    $mailerSettings = [
        'mail_transport' => (string) ($options['mail_transport'] ?? 'null'),
        'smtp_host' => (string) ($options['smtp_host'] ?? ''),
        'smtp_port' => (int) ($options['smtp_port'] ?? 587),
        'smtp_username' => (string) ($options['smtp_username'] ?? ''),
        'smtp_password' => (string) ($options['smtp_password'] ?? ''),
        'smtp_encryption' => (string) ($options['smtp_encryption'] ?? 'tls'),
        'smtp_timeout_seconds' => (int) ($options['smtp_timeout_seconds'] ?? 10),
    ];

    $emailTemplates = isset($options['email_templates']) && is_array($options['email_templates'])
        ? $options['email_templates']
        : [];
    $emailTemplateLocale = isset($options['email_template_locale']) && is_string($options['email_template_locale'])
        ? trim($options['email_template_locale'])
        : 'en';
    $emailTemplateRoots = [__DIR__ . '/../templates/email'];
    if (isset($options['email_template_roots']) && is_array($options['email_template_roots'])) {
        $configuredRoots = [];
        foreach ($options['email_template_roots'] as $root) {
            if (!is_string($root) || trim($root) === '') {
                continue;
            }

            $configuredRoots[] = trim($root);
        }

        if ($configuredRoots !== []) {
            $emailTemplateRoots = $configuredRoots;
        }
    }
    $adminNotificationRecipients = [];
    if (isset($options['admin_registration_notify_to'])) {
        $configuredRecipients = $options['admin_registration_notify_to'];
        if (is_string($configuredRecipients)) {
            $configuredRecipients = explode(',', $configuredRecipients);
        }

        if (is_array($configuredRecipients)) {
            foreach ($configuredRecipients as $recipient) {
                if (!is_string($recipient) || trim($recipient) === '') {
                    continue;
                }

                $adminNotificationRecipients[] = trim($recipient);
            }
        }
    }
    $verificationLinkTemplate = isset($options['verification_link_template']) && is_string($options['verification_link_template'])
        ? trim($options['verification_link_template'])
        : '';

    $users = new PdoUserRepository($sharedPdo);
    $profileFields = new PdoUserProfileFieldRepository($sharedPdo);
    $profileDefinitions = new PdoProfileFieldDefinitionRepository($sharedPdo);
    $roles = new PdoRoleRepository($sharedPdo);
    $profilePolicy = new DatabaseProfileFieldPolicy($profileDefinitions);
    $riskEngine = new BasicRiskEngine();
    $audit = new PdoAuditLogger($sharedPdo, $logger);

    $emailVerification = new EmailVerificationService(
        $sharedPdo,
        $tokenService,
        $users,
        $audit,
        $requestContext,
        $config->emailTokenTtlSeconds,
        $logger,
    );

    $mailer = MailerFactory::create($config, $mailerSettings);
    $emailTemplateProvider = new FileEmailTemplateProvider(
        templateRoots: $emailTemplateRoots,
        defaultLocale: $emailTemplateLocale,
        fallbackProvider: new ConfigurableEmailTemplateProvider($emailTemplates),
    );

    $passwordReset = new PasswordResetService(
        $sharedPdo,
        $users,
        $tokenService,
        new PasswordHasher(),
        $audit,
        $requestContext,
        $mailer,
        $emailTemplateProvider,
        $config->passwordResetTokenTtlSeconds,
        $logger,
    );

    $rememberMe = new RememberMeService($sharedPdo, $tokenService);

    $authService = new AuthService(
        users: $users,
        passwordHasher: new PasswordHasher(),
        auditLogger: $audit,
        profileFields: $profileFields,
        profileFieldPolicy: $profilePolicy,
        rateLimiter: new PdoRateLimiter($sharedPdo),
        emailVerification: $emailVerification,
        mailer: $mailer,
        emailTemplates: $emailTemplateProvider,
        rememberMeService: $rememberMe,
        roles: $roles,
        riskEngine: $riskEngine,
        stepUpService: new NullStepUpService(),
        events: new NullEventDispatcher(),
        ipBindingMode: $config->ipBindingMode,
        bindUserAgent: $config->bindUserAgent,
        requestContext: $requestContext,
        verificationLinkTemplate: $verificationLinkTemplate,
        adminRegistrationNotificationRecipients: $adminNotificationRecipients,
        pdo: $sharedPdo,
        logger: $logger,
    );

    return [
        'config' => $config,
        'auth_json' => new AuthJsonController($authService),
    ];
}

$hostPdo = new \PDO(
    getenv('NEXUS_DB_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4',
    getenv('NEXUS_DB_USER') ?: 'root',
    getenv('NEXUS_DB_PASS') ?: '',
    [
        \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        \PDO::ATTR_EMULATE_PREPARES => false,
    ]
);

$module = bootstrapNexusModule($hostPdo);
$authJson = $module['auth_json'] instanceof AuthJsonController ? $module['auth_json'] : null;

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($authJson instanceof AuthJsonController && $method === 'POST' && $path === '/host/auth/login') {
    $result = $authJson->login($_POST);
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($authJson instanceof AuthJsonController && $method === 'POST' && $path === '/host/auth/register') {
    $result = $authJson->register($_POST);
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

http_response_code(404);
header('Content-Type: application/json');
echo json_encode(['ok' => false, 'message' => 'Not found'], JSON_THROW_ON_ERROR);
