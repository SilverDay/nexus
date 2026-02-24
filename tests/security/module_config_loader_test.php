<?php

declare(strict_types=1);

use Nexus\DropInUser\Config\ModuleConfigLoader;

require __DIR__ . '/../../vendor/autoload.php';

$tmpConfig = tempnam(sys_get_temp_dir(), 'nexus_cfg_');
if (!is_string($tmpConfig) || $tmpConfig === '') {
    throw new RuntimeException('Unable to create temp config file.');
}

$configPhp = <<<'PHP'
<?php

return [
    'db_dsn' => 'mysql:host=cfg-db;port=3306;dbname=cfg;charset=utf8mb4',
    'db_user' => 'cfg_user',
    'db_password' => 'cfg_pass',
    'from_email' => 'module@example.test',
    'from_name' => 'Module From File',
    'email_token_ttl_seconds' => 1234,
    'password_reset_token_ttl_seconds' => 4321,
    'secure_cookies' => false,
    'same_site' => 'Strict',
    'ip_binding_mode' => 'off',
    'bind_user_agent' => false,
    'expose_debug_tokens' => true,
    'totp_key' => 'totp-from-file',
    'passkey_webauthn_enabled' => true,
    'profile_fields' => [
        'office' => [
            'label' => 'Office',
            'required' => false,
            'max_length' => 80,
            'user_visible' => true,
            'user_editable' => true,
        ],
    ],
];
PHP;

file_put_contents($tmpConfig, $configPhp);

$loaded = ModuleConfigLoader::load($tmpConfig);
$config = $loaded['config'];

assert($config->dbDsn === 'mysql:host=cfg-db;port=3306;dbname=cfg;charset=utf8mb4');
assert($config->dbUser === 'cfg_user');
assert($config->dbPassword === 'cfg_pass');
assert($config->fromEmail === 'module@example.test');
assert($config->fromName === 'Module From File');
assert($config->emailTokenTtlSeconds === 1234);
assert($config->passwordResetTokenTtlSeconds === 4321);
assert($config->secureCookies === false);
assert($config->sameSite === 'Strict');
assert($config->ipBindingMode === 'off');
assert($config->bindUserAgent === false);
assert($config->exposeDebugTokens === true);

assert(isset($loaded['settings']['totp_key']) && $loaded['settings']['totp_key'] === 'totp-from-file');
assert(isset($loaded['settings']['passkey_webauthn_enabled']) && $loaded['settings']['passkey_webauthn_enabled'] === true);
assert(is_array($loaded['profile_fields']) && isset($loaded['profile_fields']['office']));

unlink($tmpConfig);

echo "module_config_loader_test: ok\n";
