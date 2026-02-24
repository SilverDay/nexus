<?php

declare(strict_types=1);

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\PasskeyCeremonyValidatorInterface;
use Nexus\DropInUser\Observability\RequestContext;
use Nexus\DropInUser\Security\TokenService;
use Nexus\DropInUser\Service\DatabasePasskeyService;

require __DIR__ . '/../../vendor/autoload.php';

if (!extension_loaded('pdo_mysql')) {
    echo "database_passkey_service_payload_test: skipped (pdo_mysql extension not available)\n";
    exit(0);
}

$dsn = getenv('NEXUS_DB_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4';
$user = getenv('NEXUS_DB_USER') ?: 'root';
$pass = getenv('NEXUS_DB_PASS') ?: '';

try {
    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (Throwable) {
    echo "database_passkey_service_payload_test: skipped (database unavailable)\n";
    exit(0);
}

$requiredTables = ['users', 'user_passkey_credentials', 'passkey_challenges'];
foreach ($requiredTables as $tableName) {
    $check = $pdo->prepare('SHOW TABLES LIKE :table_name');
    $check->execute(['table_name' => $tableName]);
    if ($check->fetchColumn() === false) {
        throw new RuntimeException('Required schema is missing table: ' . $tableName . '. Run migrations before this test.');
    }
}

$testUserId = random_int(500000, 900000);
$testUsername = 'phase2_user_' . $testUserId;
$testEmail = 'phase2_user_' . $testUserId . '@example.com';

$pdo->prepare('DELETE FROM passkey_challenges WHERE user_id = :user_id')->execute(['user_id' => $testUserId]);
$pdo->prepare('DELETE FROM user_passkey_credentials WHERE user_id = :user_id')->execute(['user_id' => $testUserId]);
$pdo->prepare('DELETE FROM users WHERE id = :id')->execute(['id' => $testUserId]);

$insertUser = $pdo->prepare(
    'INSERT INTO users (id, username, email, real_name, password_hash, status, deleted_at)
     VALUES (:id, :username, :email, :real_name, :password_hash, :status, NULL)'
);
$insertUser->execute([
    'id' => $testUserId,
    'username' => $testUsername,
    'email' => $testEmail,
    'real_name' => 'Phase Two User',
    'password_hash' => password_hash('CorrectHorseBatteryStaple!123', PASSWORD_ARGON2ID),
    'status' => 'active',
]);

$audit = new class () implements AuditLoggerInterface {
    public function log(string $eventType, ?int $actorUserId, ?int $targetUserId, array $context = []): void
    {
    }
};

$validator = new class () implements PasskeyCeremonyValidatorInterface {
    public function createRegistrationOptions(array $context): array
    {
        return [
            'challenge' => (string) ($context['challenge'] ?? ''),
            'rp' => ['id' => (string) ($context['rp_id'] ?? '')],
        ];
    }

    public function validateRegistrationResponse(array $context, array $attestationResponse): ?array
    {
        if (!isset($context['user']) || !is_array($context['user'])) {
            return null;
        }

        return [
            'credential_id' => 'cred-nested-1',
            'public_key' => 'pubkey-nested-1',
            'sign_count' => 1,
            'transports' => ['internal'],
            'aaguid' => '00000000-0000-0000-0000-000000000000',
        ];
    }

    public function createAuthenticationOptions(array $context): array
    {
        return [
            'challenge' => (string) ($context['challenge'] ?? ''),
            'rpId' => (string) ($context['rp_id'] ?? ''),
        ];
    }

    public function validateAuthenticationResponse(array $context, array $assertionResponse): ?array
    {
        $stored = $context['stored_credential'] ?? null;
        if (!is_array($stored) || !isset($stored['user_id'], $stored['credential_id'])) {
            return null;
        }

        return [
            'user_id' => (int) $stored['user_id'],
            'credential_id' => (string) $stored['credential_id'],
            'new_sign_count' => 7,
        ];
    }
};

$service = new DatabasePasskeyService(
    $pdo,
    new TokenService(),
    $audit,
    new RequestContext(new TokenService()),
    $validator,
    '127.0.0.1',
    'http://127.0.0.1',
    'Nexus User Module',
);

$registrationOptions = $service->beginRegistration($testUserId);
assert(isset($registrationOptions['challenge']) && is_string($registrationOptions['challenge']) && $registrationOptions['challenge'] !== '');
$registrationChallenge = (string) $registrationOptions['challenge'];

$registrationPayload = [
    'publicKeyCredential' => [
        'id' => 'cred-nested-1',
        'challenge' => $registrationChallenge,
        'response' => [],
    ],
];

assert($service->finishRegistration($testUserId, $registrationPayload) === true);

$credentialLookup = $pdo->prepare('SELECT user_id, credential_id, sign_count FROM user_passkey_credentials WHERE credential_id = :credential_id LIMIT 1');
$credentialLookup->execute(['credential_id' => 'cred-nested-1']);
$credentialRow = $credentialLookup->fetch();
assert(is_array($credentialRow));
assert((int) $credentialRow['user_id'] === $testUserId);
assert((int) $credentialRow['sign_count'] === 1);

$authenticationOptions = $service->beginAuthentication($testUserId);
assert(isset($authenticationOptions['challenge']) && is_string($authenticationOptions['challenge']) && $authenticationOptions['challenge'] !== '');
$authenticationChallenge = (string) $authenticationOptions['challenge'];

$authenticationPayload = [
    'user_id' => $testUserId,
    'publicKeyCredential' => [
        'id' => 'cred-nested-1',
        'challenge' => $authenticationChallenge,
        'response' => [],
    ],
];

$resolvedUserId = $service->finishAuthentication($authenticationPayload);
assert($resolvedUserId === $testUserId);

$signCountLookup = $pdo->prepare('SELECT sign_count FROM user_passkey_credentials WHERE credential_id = :credential_id LIMIT 1');
$signCountLookup->execute(['credential_id' => 'cred-nested-1']);
$updatedSignCount = $signCountLookup->fetchColumn();
assert(is_numeric($updatedSignCount));
assert((int) $updatedSignCount === 7);

$pdo->prepare('DELETE FROM passkey_challenges WHERE user_id = :user_id')->execute(['user_id' => $testUserId]);
$pdo->prepare('DELETE FROM user_passkey_credentials WHERE user_id = :user_id')->execute(['user_id' => $testUserId]);
$pdo->prepare('DELETE FROM users WHERE id = :id')->execute(['id' => $testUserId]);

echo "database_passkey_service_payload_test: ok\n";
