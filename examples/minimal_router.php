<?php

declare(strict_types=1);

use Nexus\DropInUser\Audit\PdoAuditLogger;
use Nexus\DropInUser\Config\ModuleConfig;
use Nexus\DropInUser\Config\ModuleConfigLoader;
use Nexus\DropInUser\Config\ProfileFieldConfig;
use Nexus\DropInUser\Controller\AdminProfileFieldHtmlController;
use Nexus\DropInUser\Controller\AdminProfileFieldJsonController;
use Nexus\DropInUser\Controller\AdminUserJsonController;
use Nexus\DropInUser\Controller\AuthJsonController;
use Nexus\DropInUser\Controller\AuthHtmlController;
use Nexus\DropInUser\Controller\PasskeyHtmlController;
use Nexus\DropInUser\Controller\PasskeyJsonController;
use Nexus\DropInUser\Controller\ProfileHtmlController;
use Nexus\DropInUser\Controller\ProfileJsonController;
use Nexus\DropInUser\Controller\SessionHtmlController;
use Nexus\DropInUser\Controller\SessionJsonController;
use Nexus\DropInUser\Controller\TotpHtmlController;
use Nexus\DropInUser\Database\PdoConnectionFactory;
use Nexus\DropInUser\Event\NullEventDispatcher;
use Nexus\DropInUser\Mail\ConfigurableEmailTemplateProvider;
use Nexus\DropInUser\Mail\FileEmailTemplateProvider;
use Nexus\DropInUser\Mail\MailerFactory;
use Nexus\DropInUser\Observability\RequestContext;
use Nexus\DropInUser\Oidc\GoogleOidcProvider;
use Nexus\DropInUser\Profile\DatabaseProfileFieldPolicy;
use Nexus\DropInUser\RateLimit\PdoRateLimiter;
use Nexus\DropInUser\Repository\PdoProfileFieldDefinitionRepository;
use Nexus\DropInUser\Repository\PdoRoleRepository;
use Nexus\DropInUser\Repository\PdoUserProfileFieldRepository;
use Nexus\DropInUser\Repository\PdoUserRepository;
use Nexus\DropInUser\Risk\BasicRiskEngine;
use Nexus\DropInUser\Security\CsrfService;
use Nexus\DropInUser\Security\PasswordHasher;
use Nexus\DropInUser\Security\SecurityHeaders;
use Nexus\DropInUser\Security\TokenService;
use Nexus\DropInUser\Service\AdminUserService;
use Nexus\DropInUser\Service\AdminProfileFieldService;
use Nexus\DropInUser\Service\AuthService;
use Nexus\DropInUser\Service\DatabasePasskeyService;
use Nexus\DropInUser\Service\EmailVerificationService;
use Nexus\DropInUser\Service\NullPasskeyCeremonyValidator;
use Nexus\DropInUser\Service\NullRecoveryCodeService;
use Nexus\DropInUser\Service\NullTotpService;
use Nexus\DropInUser\Service\NullStepUpService;
use Nexus\DropInUser\Service\OidcLoginService;
use Nexus\DropInUser\Service\PasskeyCredentialService;
use Nexus\DropInUser\Service\PasswordResetService;
use Nexus\DropInUser\Service\ProfileService;
use Nexus\DropInUser\Service\RecoveryCodeService;
use Nexus\DropInUser\Service\RememberMeService;
use Nexus\DropInUser\Service\SessionDeviceService;
use Nexus\DropInUser\Service\SessionManager;
use Nexus\DropInUser\Service\TotpService;
use Nexus\DropInUser\Service\TotpStepUpService;
use Nexus\DropInUser\Service\WebAuthnPasskeyCeremonyValidator;
use Nexus\DropInUser\View\PhpTemplateRenderer;
use Nexus\DropInUser\View\TemplateLoader;
use Psr\Log\NullLogger;

require __DIR__ . '/../vendor/autoload.php';

$configFilePath = (static function (): ?string {
    if (defined('NEXUS_CONFIG_FILE_PATH') && is_string(NEXUS_CONFIG_FILE_PATH) && trim(NEXUS_CONFIG_FILE_PATH) !== '') {
        return trim(NEXUS_CONFIG_FILE_PATH);
    }

    $serverValue = $_SERVER['NEXUS_CONFIG_FILE'] ?? null;
    if (is_string($serverValue) && trim($serverValue) !== '') {
        return trim($serverValue);
    }

    $envValue = getenv('NEXUS_CONFIG_FILE');
    if (is_string($envValue) && trim($envValue) !== '') {
        return trim($envValue);
    }

    $localDefault = __DIR__ . '/config/module.config.php';

    return is_file($localDefault) ? $localDefault : null;
})();
$bootstrap = ModuleConfigLoader::load($configFilePath);

/** @var ModuleConfig $config */
$config = $bootstrap['config'];
$settings = is_array($bootstrap['settings']) ? $bootstrap['settings'] : [];

$pdo = $bootstrap['pdo'] instanceof \PDO
    ? $bootstrap['pdo']
    : PdoConnectionFactory::create($config->dbDsn, $config->dbUser, $config->dbPassword);
$users = new PdoUserRepository($pdo);
$userProfileFields = new PdoUserProfileFieldRepository($pdo);
$profileFieldDefinitions = new PdoProfileFieldDefinitionRepository($pdo);
$roles = new PdoRoleRepository($pdo);
$tokenService = new TokenService();
$requestContext = new RequestContext($tokenService);
$logger = new NullLogger();
$audit = new PdoAuditLogger($pdo, $logger);
$profileFieldDefinitionSeed = is_array($bootstrap['profile_fields']) && $bootstrap['profile_fields'] !== []
    ? $bootstrap['profile_fields']
    : [
        'department' => [
            'label' => 'Department',
            'required' => false,
            'max_length' => 120,
            'user_visible' => true,
            'user_editable' => true,
        ],
        'timezone' => [
            'label' => 'Timezone',
            'required' => false,
            'max_length' => 120,
            'pattern' => '/^[A-Za-z_\/+\-]{2,120}$/',
            'user_visible' => true,
            'user_editable' => true,
        ],
    ];

$profileFieldConfig = new ProfileFieldConfig($profileFieldDefinitionSeed);
foreach ($profileFieldConfig->definitions() as $fieldKey => $definition) {
    $profileFieldDefinitions->upsertDefinition($fieldKey, $definition);
}

$profileFieldPolicy = new DatabaseProfileFieldPolicy($profileFieldDefinitions);
$riskEngine = new BasicRiskEngine();
$emailVerification = new EmailVerificationService($pdo, $tokenService, $users, $audit, $requestContext, $config->emailTokenTtlSeconds, $logger);
$rememberMeService = new RememberMeService($pdo, $tokenService);
$sessionManager = new SessionManager($pdo, $riskEngine, $requestContext, $config->ipBindingMode, $config->bindUserAgent);

$totpKey = trim((string) ($settings['totp_key'] ?? (getenv('NEXUS_TOTP_KEY') ?: '')));
$totpService = $totpKey !== ''
    ? new TotpService($pdo, $audit, $requestContext, $totpKey, $config->fromName)
    : new NullTotpService();
$recoveryCodeService = $totpService instanceof NullTotpService
    ? new NullRecoveryCodeService()
    : new RecoveryCodeService($pdo, $tokenService, $audit, $requestContext);
$stepUpService = $totpService instanceof NullTotpService
    ? new NullStepUpService()
    : new TotpStepUpService($totpService, $recoveryCodeService, $pdo, $audit, $requestContext);

$googleOidcClientId = trim((string) ($settings['google_oidc_client_id'] ?? (getenv('NEXUS_GOOGLE_OIDC_CLIENT_ID') ?: '')));
$googleOidcClientSecret = trim((string) ($settings['google_oidc_client_secret'] ?? (getenv('NEXUS_GOOGLE_OIDC_CLIENT_SECRET') ?: '')));
$googleOidcRedirectUri = trim((string) ($settings['google_oidc_redirect_uri'] ?? (getenv('NEXUS_GOOGLE_OIDC_REDIRECT_URI') ?: '')));
$googleOidcProvider = $googleOidcClientId !== '' && $googleOidcClientSecret !== '' && $googleOidcRedirectUri !== ''
    ? new GoogleOidcProvider($googleOidcClientId, $googleOidcClientSecret, $googleOidcRedirectUri)
    : null;
$oidcLoginService = new OidcLoginService(
    $googleOidcProvider,
    $users,
    $roles,
    new PasswordHasher(),
    $audit,
    $requestContext,
    $pdo,
    $logger,
);

$emailTemplateLocale = isset($settings['email_template_locale']) && is_string($settings['email_template_locale'])
    ? trim($settings['email_template_locale'])
    : 'en';
$emailTemplateRoots = [__DIR__ . '/../templates/email'];
if (isset($settings['email_template_roots']) && is_array($settings['email_template_roots'])) {
    $configuredRoots = [];
    foreach ($settings['email_template_roots'] as $root) {
        if (!is_string($root) || trim($root) === '') {
            continue;
        }

        $configuredRoots[] = trim($root);
    }

    if ($configuredRoots !== []) {
        $emailTemplateRoots = $configuredRoots;
    }
}

$templateFallbacks = isset($settings['email_templates']) && is_array($settings['email_templates'])
    ? $settings['email_templates']
    : [];
$verificationLinkTemplate = isset($settings['verification_link_template']) && is_string($settings['verification_link_template'])
    ? trim($settings['verification_link_template'])
    : '';
if ($verificationLinkTemplate === '') {
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '127.0.0.1:8080');
    $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http';
    $verificationLinkTemplate = $scheme . '://' . $host . '/verify-email?token={{token}}';
}
$adminNotificationRecipients = [];
if (isset($settings['admin_registration_notify_to'])) {
    $configuredRecipients = $settings['admin_registration_notify_to'];
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
$mailer = MailerFactory::create($config, $settings);
$emailTemplateProvider = new FileEmailTemplateProvider(
    templateRoots: $emailTemplateRoots,
    defaultLocale: $emailTemplateLocale,
    fallbackProvider: new ConfigurableEmailTemplateProvider($templateFallbacks),
);
$passwordReset = new PasswordResetService(
    $pdo,
    $users,
    $tokenService,
    new PasswordHasher(),
    $audit,
    $requestContext,
    $mailer,
    $emailTemplateProvider,
    $config->passwordResetTokenTtlSeconds,
    $logger
);

$auth = new AuthService(
    users: $users,
    passwordHasher: new PasswordHasher(),
    auditLogger: $audit,
    profileFields: $userProfileFields,
    profileFieldPolicy: $profileFieldPolicy,
    rateLimiter: new PdoRateLimiter($pdo),
    emailVerification: $emailVerification,
    mailer: $mailer,
    emailTemplates: $emailTemplateProvider,
    rememberMeService: $rememberMeService,
    roles: $roles,
    riskEngine: $riskEngine,
    stepUpService: $stepUpService,
    events: new NullEventDispatcher(),
    ipBindingMode: $config->ipBindingMode,
    bindUserAgent: $config->bindUserAgent,
    requestContext: $requestContext,
    verificationLinkTemplate: $verificationLinkTemplate,
    adminRegistrationNotificationRecipients: $adminNotificationRecipients,
    pdo: $pdo,
    logger: $logger,
);

$authController = new AuthJsonController($auth);
$adminController = new AdminUserJsonController(new AdminUserService($pdo, $roles, $audit, $requestContext, $logger));
$adminProfileFieldService = new AdminProfileFieldService($roles, $profileFieldDefinitions, $userProfileFields, $pdo, $audit, $requestContext);
$adminProfileFieldController = new AdminProfileFieldJsonController(
    $adminProfileFieldService
);
$csrf = new CsrfService();
$profileService = new ProfileService($pdo, $userProfileFields, $profileFieldPolicy, $audit, $requestContext);
$profileJsonController = new ProfileJsonController($profileService);
$sessionDeviceService = new SessionDeviceService($pdo, $audit, $requestContext);
$sessionJsonController = new SessionJsonController($sessionDeviceService);
$passkeyCredentialService = new PasskeyCredentialService($pdo, $audit, $requestContext);
$passkeyHost = trim((string) ($_SERVER['HTTP_HOST'] ?? '127.0.0.1'));
$passkeyRpId = explode(':', $passkeyHost)[0] ?: '127.0.0.1';
$passkeyOrigin = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http') . '://' . $passkeyHost;
$passkeyWebAuthnEnabledRaw = $settings['passkey_webauthn_enabled'] ?? (getenv('NEXUS_PASSKEY_WEBAUTHN_ENABLED') ?: '');
$enableWebAuthnPasskeys = is_bool($passkeyWebAuthnEnabledRaw)
    ? $passkeyWebAuthnEnabledRaw
    : in_array(strtolower(trim((string) $passkeyWebAuthnEnabledRaw)), ['1', 'true', 'yes', 'on'], true);
$passkeyValidator = $enableWebAuthnPasskeys
    ? new WebAuthnPasskeyCeremonyValidator($passkeyRpId, $passkeyOrigin, $config->fromName)
    : new NullPasskeyCeremonyValidator();
$passkeyController = new PasskeyJsonController(
    new DatabasePasskeyService(
        $pdo,
        $tokenService,
        $audit,
        $requestContext,
        $passkeyValidator,
        $passkeyRpId,
        $passkeyOrigin,
        $config->fromName,
    ),
    $passkeyCredentialService,
);
$htmlController = new AuthHtmlController(
    new PhpTemplateRenderer(new TemplateLoader([
        __DIR__ . '/../templates',
    ])),
    $auth,
    $emailVerification,
    $passwordReset,
    $profileFieldPolicy,
    $csrf,
);
$profileHtmlController = new ProfileHtmlController(
    $profileService,
    new PhpTemplateRenderer(new TemplateLoader([
        __DIR__ . '/../templates',
    ])),
    $csrf,
);
$passkeyHtmlController = new PasskeyHtmlController(
    new PhpTemplateRenderer(new TemplateLoader([
        __DIR__ . '/../templates',
    ])),
    $passkeyCredentialService,
    $csrf,
);
$sessionHtmlController = new SessionHtmlController(
    new PhpTemplateRenderer(new TemplateLoader([
        __DIR__ . '/../templates',
    ])),
    $sessionDeviceService,
    $csrf,
);
$adminProfileFieldHtmlController = new AdminProfileFieldHtmlController(
    $adminProfileFieldService,
    new PhpTemplateRenderer(new TemplateLoader([
        __DIR__ . '/../templates',
    ])),
    $csrf,
);
$totpHtmlController = new TotpHtmlController(
    new PhpTemplateRenderer(new TemplateLoader([
        __DIR__ . '/../templates',
    ])),
    $totpService,
    $recoveryCodeService,
    $stepUpService,
    $csrf,
);

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $config->secureCookies,
    'httponly' => true,
    'samesite' => $config->sameSite,
]);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

if (!isset($_SESSION['nexus_user_id']) && isset($_COOKIE['nexus_remember']) && is_string($_COOKIE['nexus_remember'])) {
    $remember = $rememberMeService->consumeAndRotate($_COOKIE['nexus_remember']);
    if (is_array($remember) && isset($remember['userId'], $remember['rotatedToken'])) {
        session_regenerate_id(true);
        $_SESSION['nexus_user_id'] = $remember['userId'];
        setcookie('nexus_remember', $remember['rotatedToken'], [
            'expires' => time() + 60 * 60 * 24 * 30,
            'path' => '/',
            'secure' => $config->secureCookies,
            'httponly' => true,
            'samesite' => $config->sameSite,
        ]);
    }
}

$actorUserId = isset($_SESSION['nexus_user_id']) ? (int) $_SESSION['nexus_user_id'] : 0;
if ($actorUserId > 0 && !$sessionManager->validateCurrentSession($actorUserId)) {
    $_SESSION = [];
    session_destroy();
    $actorUserId = 0;
}

(new SecurityHeaders())->emit();
header('X-Request-Id: ' . $requestContext->requestId());

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($method === 'GET' && $path === '/ui/register') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->showRegister();
    exit;
}

if ($method === 'GET' && $path === '/ui/login') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->showLogin();
    exit;
}

if ($method === 'GET' && $path === '/oidc/google/start') {
    $authorizationUrl = $oidcLoginService->startGoogle();
    if (!is_string($authorizationUrl) || $authorizationUrl === '') {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode([
            'ok' => false,
            'message' => 'External login is not available.',
        ], JSON_THROW_ON_ERROR);
        exit;
    }

    header('Location: ' . $authorizationUrl, true, 302);
    exit;
}

if ($method === 'GET' && $path === '/oidc/google/callback') {
    $result = $oidcLoginService->handleGoogleCallback($_GET);
    if (($result['ok'] ?? false) === true) {
        header('Location: /ui/profile', true, 303);
        exit;
    }

    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode($result, JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'GET' && $path === '/ui/verify-email') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->showVerifyEmail();
    exit;
}

if ($method === 'GET' && $path === '/ui/password-reset/request') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->showPasswordResetRequest();
    exit;
}

if ($method === 'GET' && $path === '/ui/password-reset/confirm') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->showPasswordResetConfirm();
    exit;
}

if ($method === 'GET' && $path === '/ui/totp/enroll') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    echo $totpHtmlController->showEnrollment();
    exit;
}

if ($method === 'GET' && $path === '/ui/step-up/verify') {
    header('Content-Type: text/html; charset=utf-8');
    echo $totpHtmlController->showStepUp();
    exit;
}

if ($method === 'GET' && $path === '/ui/passkeys') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    echo $passkeyHtmlController->show($actorUserId);
    exit;
}

if ($method === 'GET' && $path === '/ui/sessions') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    echo $sessionHtmlController->show($actorUserId, session_id());
    exit;
}

if ($method === 'POST' && str_starts_with((string) $path, '/ui/')) {
    if (!$csrf->validate(isset($_POST['csrf_token']) ? (string) $_POST['csrf_token'] : null)) {
        http_response_code(400);
        header('Content-Type: text/html; charset=utf-8');
        echo '<h1>Invalid request</h1>';
        exit;
    }
}

if ($method === 'POST' && $path === '/ui/register') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->register($_POST);
    exit;
}

if ($method === 'POST' && $path === '/ui/login') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->login($_POST);
    exit;
}

if ($method === 'POST' && $path === '/ui/verify-email') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->verifyEmail($_POST);
    exit;
}

if ($method === 'POST' && $path === '/ui/password-reset/request') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->requestPasswordReset($_POST);
    exit;
}

if ($method === 'POST' && $path === '/ui/password-reset/confirm') {
    header('Content-Type: text/html; charset=utf-8');
    echo $htmlController->confirmPasswordReset($_POST);
    exit;
}

if ($method === 'POST' && $path === '/ui/totp/enroll/begin') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    echo $totpHtmlController->beginEnrollment($actorUserId, $_POST);
    exit;
}

if ($method === 'POST' && $path === '/ui/totp/enroll/confirm') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    echo $totpHtmlController->confirmEnrollment($actorUserId, $_POST);
    exit;
}

if ($method === 'POST' && $path === '/ui/step-up/verify') {
    header('Content-Type: text/html; charset=utf-8');
    echo $totpHtmlController->verifyStepUp($_POST);
    exit;
}

if ($method === 'POST' && $path === '/ui/recovery-codes/regenerate') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    echo $totpHtmlController->regenerateRecoveryCodes($actorUserId);
    exit;
}

if ($method === 'POST' && $path === '/ui/passkeys/revoke') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    echo $passkeyHtmlController->revoke($actorUserId, (string) ($_POST['credential_id'] ?? ''));
    exit;
}

if ($method === 'POST' && $path === '/ui/sessions/revoke') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    $sessionId = (string) ($_POST['session_id'] ?? '');
    $isCurrent = $sessionId !== '' && hash_equals(session_id(), $sessionId);

    header('Content-Type: text/html; charset=utf-8');
    $html = $sessionHtmlController->revoke($actorUserId, session_id(), $sessionId);

    if ($isCurrent) {
        $_SESSION = [];
        session_destroy();
    }

    echo $html;
    exit;
}

$csrfInputToken = isset($_SERVER['HTTP_X_CSRF_TOKEN']) && is_string($_SERVER['HTTP_X_CSRF_TOKEN'])
    ? $_SERVER['HTTP_X_CSRF_TOKEN']
    : (isset($_POST['csrf_token']) ? (string) $_POST['csrf_token'] : null);

if ($method === 'POST' && ($path === '/profile' || str_starts_with((string) $path, '/admin/'))) {
    if ($actorUserId <= 0) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
        exit;
    }

    if (!$csrf->validate($csrfInputToken)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Invalid request'], JSON_THROW_ON_ERROR);
        exit;
    }
}

if ($method === 'POST' && str_starts_with((string) $path, '/totp/')) {
    if ($actorUserId <= 0) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
        exit;
    }

    if (!$csrf->validate($csrfInputToken)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Invalid request'], JSON_THROW_ON_ERROR);
        exit;
    }
}

if ($method === 'POST' && str_starts_with((string) $path, '/recovery-codes/')) {
    if ($actorUserId <= 0) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
        exit;
    }

    if (!$csrf->validate($csrfInputToken)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Invalid request'], JSON_THROW_ON_ERROR);
        exit;
    }
}

if ($method === 'POST' && str_starts_with((string) $path, '/passkeys/')) {
    if ((str_starts_with((string) $path, '/passkeys/register/') || $path === '/passkeys/revoke') && $actorUserId <= 0) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
        exit;
    }

    if (!$csrf->validate($csrfInputToken)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Invalid request'], JSON_THROW_ON_ERROR);
        exit;
    }
}

if ($method === 'POST' && str_starts_with((string) $path, '/sessions/')) {
    if ($actorUserId <= 0) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
        exit;
    }

    if (!$csrf->validate($csrfInputToken)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'message' => 'Invalid request'], JSON_THROW_ON_ERROR);
        exit;
    }
}

if ($method === 'GET' && $path === '/passkeys/list') {
    $result = $passkeyController->listCredentials($actorUserId);
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'GET' && $path === '/sessions') {
    $result = $sessionJsonController->list($actorUserId, session_id());
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'GET' && $path === '/ui/profile') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    echo $profileHtmlController->show($actorUserId);
    exit;
}

if ($method === 'GET' && $path === '/ui/admin/profile-fields') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    try {
        header('Content-Type: text/html; charset=utf-8');
        echo $adminProfileFieldHtmlController->show($actorUserId);
    } catch (RuntimeException) {
        http_response_code(403);
        echo 'Forbidden';
    }
    exit;
}

if ($method === 'GET' && $path === '/ui/admin/user/profile-fields') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    $targetUserId = isset($_GET['target_user_id']) ? (int) $_GET['target_user_id'] : 0;
    $query = isset($_GET['q']) ? (string) $_GET['q'] : '';
    $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 50;
    $offset = isset($_GET['offset']) ? (int) $_GET['offset'] : 0;
    try {
        header('Content-Type: text/html; charset=utf-8');
        echo $adminProfileFieldHtmlController->showUserProfile($actorUserId, $targetUserId, $query, $limit, $offset);
    } catch (RuntimeException) {
        http_response_code(403);
        echo 'Forbidden';
    }
    exit;
}

if ($method === 'POST' && $path === '/ui/profile') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    if (!$csrf->validate(isset($_POST['csrf_token']) ? (string) $_POST['csrf_token'] : null)) {
        http_response_code(400);
        echo 'Invalid request';
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    echo $profileHtmlController->update($actorUserId, $_POST);
    exit;
}

if ($method === 'POST' && $path === '/ui/admin/profile-fields/upsert') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    if (!$csrf->validate(isset($_POST['csrf_token']) ? (string) $_POST['csrf_token'] : null)) {
        http_response_code(400);
        echo 'Invalid request';
        exit;
    }

    try {
        header('Content-Type: text/html; charset=utf-8');
        echo $adminProfileFieldHtmlController->upsert($actorUserId, $_POST);
    } catch (RuntimeException) {
        http_response_code(403);
        echo 'Forbidden';
    }
    exit;
}

if ($method === 'POST' && $path === '/ui/admin/profile-fields/delete') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo 'Unauthorized';
        exit;
    }

    if (!$csrf->validate(isset($_POST['csrf_token']) ? (string) $_POST['csrf_token'] : null)) {
        http_response_code(400);
        echo 'Invalid request';
        exit;
    }

    try {
        header('Content-Type: text/html; charset=utf-8');
        echo $adminProfileFieldHtmlController->delete($actorUserId, $_POST);
    } catch (RuntimeException) {
        http_response_code(403);
        echo 'Forbidden';
    }
    exit;
}

if ($method === 'POST' && $path === '/register') {
    $result = $authController->register($_POST);
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/login') {
    $result = $authController->login($_POST);
    if (($result['body']['ok'] ?? false) === true && isset($result['body']['rememberMeToken']) && is_string($result['body']['rememberMeToken'])) {
        setcookie('nexus_remember', $result['body']['rememberMeToken'], [
            'expires' => time() + 60 * 60 * 24 * 30,
            'path' => '/',
            'secure' => $config->secureCookies,
            'httponly' => true,
            'samesite' => $config->sameSite,
        ]);
        unset($result['body']['rememberMeToken']);
    }

    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/verify-email') {
    $ok = $emailVerification->consume((string) ($_POST['token'] ?? ''));
    header('Content-Type: application/json');
    echo json_encode(['ok' => $ok, 'message' => $ok ? 'Email verified.' : 'Invalid verification token.'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'GET' && $path === '/verify-email') {
    $ok = $emailVerification->consume((string) ($_GET['token'] ?? ''));
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Email verification</title></head><body><main><h1>Email verification</h1><p>'
        . ($ok ? 'Your email has been verified.' : 'Invalid or expired verification token.')
        . '</p></main></body></html>';
    exit;
}

if ($method === 'POST' && $path === '/password-reset/request') {
    $token = $passwordReset->request((string) ($_POST['identifier'] ?? ''));
    $response = [
        'ok' => true,
        'message' => 'If the account exists, reset instructions were sent.',
    ];

    if ($config->exposeDebugTokens && is_string($token) && $token !== '') {
        $response['demo_token'] = $token;
    }

    header('Content-Type: application/json');
    echo json_encode($response, JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/password-reset/confirm') {
    $ok = $passwordReset->consume(
        (string) ($_POST['token'] ?? ''),
        (string) ($_POST['new_password'] ?? ''),
    );
    header('Content-Type: application/json');
    echo json_encode([
        'ok' => $ok,
        'message' => $ok ? 'Password updated.' : 'Invalid token or password policy failure.',
    ], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/totp/enroll/begin') {
    try {
        if ($actorUserId <= 0) {
            http_response_code(401);
            echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
            exit;
        }

        $uri = $totpService->beginEnrollment($actorUserId);
        header('Content-Type: application/json');
        echo json_encode(['ok' => true, 'provisioning_uri' => $uri], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'message' => 'Unable to start TOTP enrollment.'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'POST' && $path === '/totp/enroll/confirm') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
        exit;
    }

    $ok = $totpService->confirmEnrollment($actorUserId, (string) ($_POST['otp'] ?? $_POST['otp_code'] ?? ''));
    header('Content-Type: application/json');
    echo json_encode([
        'ok' => $ok,
        'message' => $ok ? 'TOTP enrollment confirmed.' : 'Unable to confirm TOTP enrollment.',
    ], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/step-up/verify') {
    $ok = $stepUpService->verifyChallenge(0, $_POST);
    header('Content-Type: application/json');
    echo json_encode([
        'ok' => $ok,
        'message' => $ok ? 'Step-up verification successful.' : 'Invalid verification code.',
    ], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/recovery-codes/regenerate') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
        exit;
    }

    $codes = $recoveryCodeService->regenerateCodes($actorUserId);
    header('Content-Type: application/json');
    echo json_encode([
        'ok' => $codes !== [],
        'codes' => $codes,
    ], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/passkeys/register/begin') {
    $result = $passkeyController->beginRegistration($actorUserId);
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/passkeys/register/finish') {
    $credential = isset($_POST['credential']) && is_array($_POST['credential'])
        ? $_POST['credential']
        : [];
    $result = $passkeyController->finishRegistration($actorUserId, $credential);
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/passkeys/authenticate/begin') {
    $requestedUserId = isset($_POST['user_id']) ? (int) $_POST['user_id'] : null;
    $result = $passkeyController->beginAuthentication($requestedUserId);
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/passkeys/authenticate/finish') {
    $assertion = isset($_POST['assertion']) && is_array($_POST['assertion'])
        ? $_POST['assertion']
        : [];
    $result = $passkeyController->finishAuthentication($assertion);

    if (($result['status'] ?? 0) === 200 && isset($result['body']['ok'], $result['body']['user_id']) && $result['body']['ok'] === true) {
        $passkeyUserId = (int) $result['body']['user_id'];
        if ($passkeyUserId > 0) {
            if (session_status() !== PHP_SESSION_ACTIVE) {
                session_start();
            }

            session_regenerate_id(true);
            $_SESSION['nexus_user_id'] = $passkeyUserId;

            $context = $requestContext->asAuditContext();
            $sessionStmt = $pdo->prepare(
                'INSERT INTO user_sessions (user_id, session_id, ip_address, ua_hash)
                 VALUES (:user_id, :session_id, :ip_address, :ua_hash)'
            );
            $sessionStmt->execute([
                'user_id' => $passkeyUserId,
                'session_id' => session_id(),
                'ip_address' => $context['source_ip'],
                'ua_hash' => $context['user_agent_hash'],
            ]);

            $updateStmt = $pdo->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
            $updateStmt->execute(['id' => $passkeyUserId]);

            $audit->log('auth.login.succeeded', $passkeyUserId, $passkeyUserId, $context);
            $result['body']['message'] = 'Login successful.';
            unset($result['body']['user_id']);
        }
    }

    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/passkeys/revoke') {
    $result = $passkeyController->revokeCredential($actorUserId, (string) ($_POST['credential_id'] ?? ''));
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/sessions/revoke') {
    $sessionId = (string) ($_POST['session_id'] ?? '');
    $isCurrent = $sessionId !== '' && hash_equals(session_id(), $sessionId);

    $result = $sessionJsonController->revoke($actorUserId, $sessionId);
    if (($result['status'] ?? 0) === 200 && $isCurrent) {
        $_SESSION = [];
        session_destroy();
    }

    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'GET' && $path === '/profile') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
        exit;
    }

    $result = $profileJsonController->get($actorUserId);
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST' && $path === '/profile') {
    if ($actorUserId <= 0) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'message' => 'Unauthorized'], JSON_THROW_ON_ERROR);
        exit;
    }

    $result = $profileJsonController->update($actorUserId, $_POST);
    header('Content-Type: application/json');
    http_response_code($result['status']);
    echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'GET' && $path === '/admin/profile-fields') {
    try {
        $result = $adminProfileFieldController->list($actorUserId);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'POST' && $path === '/admin/profile-fields/upsert') {
    try {
        $result = $adminProfileFieldController->upsert($actorUserId, $_POST);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'POST' && $path === '/admin/profile-fields/delete') {
    try {
        $result = $adminProfileFieldController->delete($actorUserId, (string) ($_POST['field_key'] ?? ''));
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'GET' && $path === '/admin/user/profile-fields') {
    $targetUserId = isset($_GET['target_user_id']) ? (int) $_GET['target_user_id'] : 0;
    try {
        $result = $adminProfileFieldController->viewUserProfile($actorUserId, $targetUserId, $_GET);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'GET' && $path === '/admin/users') {
    try {
        $result = $adminController->list($actorUserId, $_GET);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'POST' && $path === '/admin/user/update') {
    $targetUserId = (int) ($_POST['target_user_id'] ?? 0);
    try {
        $result = $adminController->update($actorUserId, $targetUserId, $_POST);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'POST' && $path === '/admin/user/assign-role') {
    $targetUserId = (int) ($_POST['target_user_id'] ?? 0);
    $role = (string) ($_POST['role'] ?? '');
    try {
        $result = $adminController->assignRole($actorUserId, $targetUserId, $role);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'POST' && $path === '/admin/user/revoke-role') {
    $targetUserId = (int) ($_POST['target_user_id'] ?? 0);
    $role = (string) ($_POST['role'] ?? '');
    try {
        $result = $adminController->revokeRole($actorUserId, $targetUserId, $role);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'POST' && $path === '/admin/user/block') {
    $targetUserId = (int) ($_POST['target_user_id'] ?? 0);
    try {
        $result = $adminController->block($actorUserId, $targetUserId);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'POST' && $path === '/admin/user/soft-delete') {
    $targetUserId = (int) ($_POST['target_user_id'] ?? 0);
    try {
        $result = $adminController->softDelete($actorUserId, $targetUserId);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

if ($method === 'POST' && $path === '/admin/user/revoke-sessions') {
    $targetUserId = (int) ($_POST['target_user_id'] ?? 0);
    try {
        $result = $adminController->revokeSessions($actorUserId, $targetUserId);
        header('Content-Type: application/json');
        http_response_code($result['status']);
        echo json_encode($result['body'], JSON_THROW_ON_ERROR);
    } catch (RuntimeException) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'message' => 'Forbidden'], JSON_THROW_ON_ERROR);
    }
    exit;
}

header('Content-Type: text/plain; charset=utf-8');
echo "Nexus Drop-In User module demo router\n";
