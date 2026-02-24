<?php

declare(strict_types=1);

use Nexus\DropInUser\Config\ModuleConfig;
use Nexus\DropInUser\Config\ModuleConfigLoader;
use Nexus\DropInUser\Database\MigrationRunner;
use Nexus\DropInUser\Database\Migrations\AddUserProfileFieldsMigration;
use Nexus\DropInUser\Database\Migrations\AddProfileFieldDefinitionsMigration;
use Nexus\DropInUser\Database\Migrations\AddAdminVisibilityToProfileFieldDefinitionsMigration;
use Nexus\DropInUser\Database\Migrations\AddTotpFactorsMigration;
use Nexus\DropInUser\Database\Migrations\AddRecoveryCodesMigration;
use Nexus\DropInUser\Database\Migrations\AddOidcIdentitiesMigration;
use Nexus\DropInUser\Database\Migrations\AddPasskeyCredentialsMigration;
use Nexus\DropInUser\Database\Migrations\AddPasskeyChallengesMigration;
use Nexus\DropInUser\Database\Migrations\InitialSchemaMigration;
use Nexus\DropInUser\Database\PdoConnectionFactory;

require __DIR__ . '/../vendor/autoload.php';

$configFilePath = (static function (array $argv): ?string {
    if (isset($argv[1]) && is_string($argv[1]) && trim($argv[1]) !== '') {
        return trim($argv[1]);
    }

    if (defined('NEXUS_CONFIG_FILE_PATH') && is_string(NEXUS_CONFIG_FILE_PATH) && trim(NEXUS_CONFIG_FILE_PATH) !== '') {
        return trim(NEXUS_CONFIG_FILE_PATH);
    }

    $envValue = getenv('NEXUS_CONFIG_FILE');
    if (is_string($envValue) && trim($envValue) !== '') {
        return trim($envValue);
    }

    $localDefault = __DIR__ . '/../examples/config/module.config.php';

    return is_file($localDefault) ? $localDefault : null;
})($argv ?? []);
$bootstrap = ModuleConfigLoader::load($configFilePath);

/** @var ModuleConfig $config */
$config = $bootstrap['config'];

$pdo = $bootstrap['pdo'] instanceof \PDO
    ? $bootstrap['pdo']
    : PdoConnectionFactory::create($config->dbDsn, $config->dbUser, $config->dbPassword);

$runner = new MigrationRunner();
$runner->run($pdo, [
    new InitialSchemaMigration(),
    new AddUserProfileFieldsMigration(),
    new AddProfileFieldDefinitionsMigration(),
    new AddAdminVisibilityToProfileFieldDefinitionsMigration(),
    new AddTotpFactorsMigration(),
    new AddRecoveryCodesMigration(),
    new AddOidcIdentitiesMigration(),
    new AddPasskeyCredentialsMigration(),
    new AddPasskeyChallengesMigration(),
]);

echo "Migrations complete.\n";
