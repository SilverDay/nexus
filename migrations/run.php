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

$configFilePath = getenv('NEXUS_CONFIG_FILE');
$bootstrap = ModuleConfigLoader::load(is_string($configFilePath) && trim($configFilePath) !== '' ? trim($configFilePath) : null);

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
