<?php

declare(strict_types=1);

use Nexus\DropInUser\Audit\PdoAuditLogger;
use Nexus\DropInUser\Config\ModuleConfig;
use Nexus\DropInUser\Config\ModuleConfigLoader;
use Nexus\DropInUser\Config\ProfileFieldConfig;
use Nexus\DropInUser\Database\PdoConnectionFactory;
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
use Nexus\DropInUser\Security\CsrfService;
use Nexus\DropInUser\Security\PasswordHasher;
use Nexus\DropInUser\Security\SecurityHeaders;
use Nexus\DropInUser\Security\TokenService;
use Nexus\DropInUser\Service\AuthService;
use Nexus\DropInUser\Service\EmailVerificationService;
use Nexus\DropInUser\Service\NullStepUpService;
use Nexus\DropInUser\Service\RememberMeService;
use Nexus\DropInUser\Service\SessionManager;
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

    $localDemoDefault = __DIR__ . '/config/module_webapp.config.php';
    if (is_file($localDemoDefault)) {
        return $localDemoDefault;
    }

    $localDefault = __DIR__ . '/config/module.config.php';

    return is_file($localDefault) ? $localDefault : null;
})();

$bootstrap = ModuleConfigLoader::load($configFilePath);

/** @var ModuleConfig $config */
$config = $bootstrap['config'];
$settings = is_array($bootstrap['settings']) ? $bootstrap['settings'] : [];

try {
    $pdo = $bootstrap['pdo'] instanceof PDO
        ? $bootstrap['pdo']
        : PdoConnectionFactory::create($config->dbDsn, $config->dbUser, $config->dbPassword);
} catch (Throwable $exception) {
    http_response_code(500);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Nexus demo setup error</title></head><body><main><h1>Nexus demo setup error</h1><p>Database connection failed. Verify PDO driver, DSN, username, password, and run migrations.</p><p><strong>Error:</strong> ' . htmlspecialchars($exception->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p></main></body></html>';
    exit;
}

$users = new PdoUserRepository($pdo);
$roles = new PdoRoleRepository($pdo);
$profileFields = new PdoUserProfileFieldRepository($pdo);
$profileFieldDefinitions = new PdoProfileFieldDefinitionRepository($pdo);

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
    ];

$profileFieldConfig = new ProfileFieldConfig($profileFieldDefinitionSeed);
foreach ($profileFieldConfig->definitions() as $fieldKey => $definition) {
    $profileFieldDefinitions->upsertDefinition($fieldKey, $definition);
}

$profilePolicy = new DatabaseProfileFieldPolicy($profileFieldDefinitions);
$tokenService = new TokenService();
$requestContext = new RequestContext($tokenService);
$logger = new NullLogger();
$audit = new PdoAuditLogger($pdo, $logger);
$riskEngine = new BasicRiskEngine();

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

$mailer = MailerFactory::create($config, $settings);
$emailTemplateProvider = new FileEmailTemplateProvider(
    templateRoots: $emailTemplateRoots,
    defaultLocale: $emailTemplateLocale,
    fallbackProvider: new ConfigurableEmailTemplateProvider($templateFallbacks),
);

$emailVerification = new EmailVerificationService(
    $pdo,
    $tokenService,
    $users,
    $audit,
    $requestContext,
    $config->emailTokenTtlSeconds,
    $logger,
);

$rememberMeService = new RememberMeService($pdo, $tokenService);
$auth = new AuthService(
    users: $users,
    passwordHasher: new PasswordHasher(),
    auditLogger: $audit,
    profileFields: $profileFields,
    profileFieldPolicy: $profilePolicy,
    rateLimiter: new PdoRateLimiter($pdo),
    emailVerification: $emailVerification,
    mailer: $mailer,
    emailTemplates: $emailTemplateProvider,
    rememberMeService: $rememberMeService,
    roles: $roles,
    riskEngine: $riskEngine,
    stepUpService: new NullStepUpService(),
    events: new NullEventDispatcher(),
    ipBindingMode: $config->ipBindingMode,
    bindUserAgent: $config->bindUserAgent,
    requestContext: $requestContext,
    verificationLinkTemplate: $verificationLinkTemplate,
    adminRegistrationNotificationRecipients: [],
    pdo: $pdo,
    logger: $logger,
);

$csrf = new CsrfService();
$sessionManager = new SessionManager($pdo, $riskEngine, $requestContext, $config->ipBindingMode, $config->bindUserAgent);

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
        $_SESSION['nexus_user_id'] = (int) $remember['userId'];
        setcookie('nexus_remember', (string) $remember['rotatedToken'], [
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
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($method === 'POST') {
    $csrfToken = isset($_POST['csrf_token']) ? (string) $_POST['csrf_token'] : null;
    if (!$csrf->validate($csrfToken)) {
        http_response_code(400);
        header('Content-Type: text/html; charset=utf-8');
        echo renderPage('Invalid request', '<p>CSRF validation failed.</p>', $actorUserId, false, null, $csrf->token());
        exit;
    }
}

if ($method === 'POST' && $path === '/register') {
    $result = $auth->register(
        (string) ($_POST['username'] ?? ''),
        (string) ($_POST['email'] ?? ''),
        (string) ($_POST['realname'] ?? ''),
        (string) ($_POST['password'] ?? ''),
        []
    );

    $_SESSION['demo_flash'] = (string) ($result['message'] ?? 'Unable to process request.');
    redirectTo(($result['ok'] ?? false) === true ? '/login' : '/register');
}

if ($method === 'POST' && $path === '/login') {
    $result = $auth->login(
        (string) ($_POST['identifier'] ?? ''),
        (string) ($_POST['password'] ?? ''),
        isset($_POST['remember_me'])
    );

    if (($result['ok'] ?? false) === true) {
        if (isset($result['rememberMeToken']) && is_string($result['rememberMeToken'])) {
            setcookie('nexus_remember', $result['rememberMeToken'], [
                'expires' => time() + 60 * 60 * 24 * 30,
                'path' => '/',
                'secure' => $config->secureCookies,
                'httponly' => true,
                'samesite' => $config->sameSite,
            ]);
        }

        $_SESSION['demo_flash'] = 'Login successful.';
        redirectTo('/user-area');
    }

    $_SESSION['demo_flash'] = (string) ($result['message'] ?? 'Invalid credentials.');
    redirectTo('/login');
}

if ($method === 'POST' && $path === '/logout') {
    if ($actorUserId > 0) {
        $stmt = $pdo->prepare('UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = :user_id AND session_id = :session_id AND revoked_at IS NULL');
        $stmt->execute([
            'user_id' => $actorUserId,
            'session_id' => session_id(),
        ]);
    }

    $_SESSION = [];
    session_destroy();
    setcookie('nexus_remember', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => $config->secureCookies,
        'httponly' => true,
        'samesite' => $config->sameSite,
    ]);
    redirectTo('/');
}

$flash = null;
if (isset($_SESSION['demo_flash']) && is_string($_SESSION['demo_flash']) && $_SESSION['demo_flash'] !== '') {
    $flash = $_SESSION['demo_flash'];
}
unset($_SESSION['demo_flash']);

$currentUser = findUserById($pdo, $actorUserId);
$isAdmin = $currentUser !== null && ($roles->hasRole($actorUserId, 'admin') || $roles->hasRole($actorUserId, 'super_admin'));

if ($method === 'GET' && $path === '/') {
    $body = '<h1>Nexus demo host app</h1>'
        . '<p>This page is provided by your host app while authentication is handled by the module services.</p>'
        . '<ul>'
        . '<li><a href="/register">Register</a></li>'
        . '<li><a href="/login">Login</a></li>'
        . '<li><a href="/user-area">User area (restricted)</a></li>'
        . '<li><a href="/admin-area">Admin area (restricted)</a></li>'
        . '<li><a href="/verify-email">Verify email by token</a> (module endpoint)</li>'
        . '</ul>';

    echo renderPage('Home', $body, $actorUserId, $isAdmin, $currentUser, $csrf->token(), $flash);
    exit;
}

if ($method === 'GET' && $path === '/register') {
    $body = '<h1>Register</h1>'
        . '<form method="post" action="/register">'
        . '<input type="hidden" name="csrf_token" value="' . h($csrf->token()) . '">'
        . '<p><label>Username <input type="text" name="username" required minlength="3" maxlength="50"></label></p>'
        . '<p><label>Email <input type="email" name="email" required></label></p>'
        . '<p><label>Real name <input type="text" name="realname" required minlength="2" maxlength="120"></label></p>'
        . '<p><label>Password <input type="password" name="password" required minlength="12"></label></p>'
        . '<p><button type="submit">Create account</button></p>'
        . '</form>';

    echo renderPage('Register', $body, $actorUserId, $isAdmin, $currentUser, $csrf->token(), $flash);
    exit;
}

if ($method === 'GET' && $path === '/login') {
    $body = '<h1>Login</h1>'
        . '<form method="post" action="/login">'
        . '<input type="hidden" name="csrf_token" value="' . h($csrf->token()) . '">'
        . '<p><label>Username or email <input type="text" name="identifier" required></label></p>'
        . '<p><label>Password <input type="password" name="password" required></label></p>'
        . '<p><label><input type="checkbox" name="remember_me" value="1"> Remember me</label></p>'
        . '<p><button type="submit">Login</button></p>'
        . '</form>';

    echo renderPage('Login', $body, $actorUserId, $isAdmin, $currentUser, $csrf->token(), $flash);
    exit;
}

if ($method === 'GET' && $path === '/user-area') {
    if ($currentUser === null) {
        $_SESSION['demo_flash'] = 'Please login first.';
        redirectTo('/login');
    }

    $body = '<h1>User area</h1>'
        . '<p>Welcome, ' . h((string) ($currentUser['real_name'] ?? $currentUser['username'] ?? 'user')) . '.</p>'
        . '<ul>'
        . '<li>User ID: ' . h((string) ($currentUser['id'] ?? '')) . '</li>'
        . '<li>Username: ' . h((string) ($currentUser['username'] ?? '')) . '</li>'
        . '<li>Email: ' . h((string) ($currentUser['email'] ?? '')) . '</li>'
        . '<li>Email verified: ' . (((string) ($currentUser['email_verified_at'] ?? '')) !== '' ? 'yes' : 'no') . '</li>'
        . '</ul>';

    echo renderPage('User area', $body, $actorUserId, $isAdmin, $currentUser, $csrf->token(), $flash);
    exit;
}

if ($method === 'GET' && $path === '/admin-area') {
    if ($currentUser === null) {
        $_SESSION['demo_flash'] = 'Please login first.';
        redirectTo('/login');
    }

    if (!$isAdmin) {
        http_response_code(403);
        $body = '<h1>Admin area</h1>'
            . '<p>Access denied. Assign role <strong>admin</strong> or <strong>super_admin</strong> to this account to view this page.</p>';
        echo renderPage('Admin area', $body, $actorUserId, $isAdmin, $currentUser, $csrf->token(), $flash);
        exit;
    }

    $roleList = $roles->rolesForUser($actorUserId);
    $body = '<h1>Admin area</h1>'
        . '<p>This is a restricted host-app page protected with module role checks.</p>'
        . '<p>Current roles: ' . h(implode(', ', $roleList)) . '</p>';

    echo renderPage('Admin area', $body, $actorUserId, $isAdmin, $currentUser, $csrf->token(), $flash);
    exit;
}

if ($method === 'GET' && $path === '/verify-email') {
    $token = isset($_GET['token']) ? (string) $_GET['token'] : '';
    $ok = $token !== '' && $emailVerification->consume($token);
    $body = '<h1>Verify email</h1>'
        . '<p>' . ($ok ? 'Email verified.' : 'Invalid or expired token.') . '</p>';
    echo renderPage('Verify email', $body, $actorUserId, $isAdmin, $currentUser, $csrf->token(), $flash);
    exit;
}

http_response_code(404);
echo renderPage('Not found', '<h1>Not found</h1><p>The requested page does not exist.</p>', $actorUserId, $isAdmin, $currentUser, $csrf->token(), $flash);

function redirectTo(string $location): never
{
    header('Location: ' . $location, true, 303);
    exit;
}

/**
 * @return array<string, mixed>|null
 */
function findUserById(PDO $pdo, int $userId): ?array
{
    if ($userId <= 0) {
        return null;
    }

    $stmt = $pdo->prepare(
        'SELECT id, username, email, real_name, email_verified_at
         FROM users
         WHERE id = :id AND deleted_at IS NULL
         LIMIT 1'
    );
    $stmt->execute(['id' => $userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return is_array($row) ? $row : null;
}

/**
 * @param array<string, mixed>|null $currentUser
 */
function renderPage(
    string $title,
    string $body,
    int $actorUserId,
    bool $isAdmin,
    ?array $currentUser,
    string $csrfToken,
    ?string $flash = null
): string {
    $identity = $currentUser === null
        ? '<p>Signed in: no</p>'
        : '<p>Signed in: yes (' . h((string) ($currentUser['username'] ?? '')) . ')</p>';

    $flashHtml = $flash !== null && $flash !== ''
        ? '<p><strong>' . h($flash) . '</strong></p>'
        : '';

    $logoutForm = $actorUserId > 0
        ? '<form method="post" action="/logout"><input type="hidden" name="csrf_token" value="' . h($csrfToken) . '"><button type="submit">Logout</button></form>'
        : '';

    $adminBadge = $isAdmin ? ' (admin)' : '';

    return '<!doctype html>'
        . '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>' . h($title) . '</title></head><body><main>'
        . '<nav><a href="/">Home</a> | <a href="/register">Register</a> | <a href="/login">Login</a> | <a href="/user-area">User area</a> | <a href="/admin-area">Admin area</a>' . $adminBadge . '</nav>'
        . $identity
        . $logoutForm
        . $flashHtml
        . $body
        . '</main></body></html>';
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
