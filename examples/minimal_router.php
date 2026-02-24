<?php

declare(strict_types=1);

use Nexus\DropInUser\Audit\PdoAuditLogger;
use Nexus\DropInUser\Config\ModuleConfig;
use Nexus\DropInUser\Config\ProfileFieldConfig;
use Nexus\DropInUser\Controller\AdminProfileFieldHtmlController;
use Nexus\DropInUser\Controller\AdminProfileFieldJsonController;
use Nexus\DropInUser\Controller\AdminUserJsonController;
use Nexus\DropInUser\Controller\AuthJsonController;
use Nexus\DropInUser\Controller\AuthHtmlController;
use Nexus\DropInUser\Controller\ProfileHtmlController;
use Nexus\DropInUser\Controller\ProfileJsonController;
use Nexus\DropInUser\Database\PdoConnectionFactory;
use Nexus\DropInUser\Event\NullEventDispatcher;
use Nexus\DropInUser\Mail\NullMailer;
use Nexus\DropInUser\Observability\RequestContext;
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
use Nexus\DropInUser\Service\EmailVerificationService;
use Nexus\DropInUser\Service\NullStepUpService;
use Nexus\DropInUser\Service\PasswordResetService;
use Nexus\DropInUser\Service\ProfileService;
use Nexus\DropInUser\Service\RememberMeService;
use Nexus\DropInUser\Service\SessionManager;
use Nexus\DropInUser\View\PhpTemplateRenderer;
use Nexus\DropInUser\View\TemplateLoader;
use Psr\Log\NullLogger;

require __DIR__ . '/../vendor/autoload.php';

$config = new ModuleConfig(
    dbDsn: getenv('NEXUS_DB_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4',
    dbUser: getenv('NEXUS_DB_USER') ?: 'root',
    dbPassword: getenv('NEXUS_DB_PASS') ?: '',
    fromEmail: 'noreply@example.com',
    fromName: 'Nexus User Module'
);

$pdo = PdoConnectionFactory::create($config->dbDsn, $config->dbUser, $config->dbPassword);
$users = new PdoUserRepository($pdo);
$userProfileFields = new PdoUserProfileFieldRepository($pdo);
$profileFieldDefinitions = new PdoProfileFieldDefinitionRepository($pdo);
$roles = new PdoRoleRepository($pdo);
$tokenService = new TokenService();
$requestContext = new RequestContext($tokenService);
$logger = new NullLogger();
$audit = new PdoAuditLogger($pdo, $logger);
$profileFieldConfig = new ProfileFieldConfig([
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
]);
foreach ($profileFieldConfig->definitions() as $fieldKey => $definition) {
    $profileFieldDefinitions->upsertDefinition($fieldKey, $definition);
}

$profileFieldPolicy = new DatabaseProfileFieldPolicy($profileFieldDefinitions);
$riskEngine = new BasicRiskEngine();
$emailVerification = new EmailVerificationService($pdo, $tokenService, $users, $audit, $requestContext, $config->emailTokenTtlSeconds, $logger);
$passwordReset = new PasswordResetService($pdo, $users, $tokenService, new PasswordHasher(), $audit, $requestContext, $config->passwordResetTokenTtlSeconds, $logger);
$rememberMeService = new RememberMeService($pdo, $tokenService);
$sessionManager = new SessionManager($pdo, $riskEngine, $requestContext, $config->ipBindingMode, $config->bindUserAgent);

$auth = new AuthService(
    users: $users,
    passwordHasher: new PasswordHasher(),
    tokenService: $tokenService,
    auditLogger: $audit,
    profileFields: $userProfileFields,
    profileFieldPolicy: $profileFieldPolicy,
    rateLimiter: new PdoRateLimiter($pdo),
    emailVerification: $emailVerification,
    mailer: new NullMailer(),
    rememberMeService: $rememberMeService,
    roles: $roles,
    riskEngine: $riskEngine,
    stepUpService: new NullStepUpService(),
    events: new NullEventDispatcher(),
    ipBindingMode: $config->ipBindingMode,
    bindUserAgent: $config->bindUserAgent,
    requestContext: $requestContext,
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
$adminProfileFieldHtmlController = new AdminProfileFieldHtmlController(
    $adminProfileFieldService,
    new PhpTemplateRenderer(new TemplateLoader([
        __DIR__ . '/../templates',
    ])),
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

$actorUserId = isset($_SESSION['nexus_user_id']) ? (int) $_SESSION['nexus_user_id'] : 0;
if ($actorUserId > 0 && !$sessionManager->validateCurrentSession($actorUserId)) {
    $_SESSION = [];
    session_destroy();
    $actorUserId = 0;
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
