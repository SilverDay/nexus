<?php

declare(strict_types=1);

use Nexus\DropInUser\Config\ModuleConfig;
use Nexus\DropInUser\Database\MigrationRunner;
use Nexus\DropInUser\Database\Migrations\AddUserProfileFieldsMigration;
use Nexus\DropInUser\Database\Migrations\AddProfileFieldDefinitionsMigration;
use Nexus\DropInUser\Database\Migrations\AddAdminVisibilityToProfileFieldDefinitionsMigration;
use Nexus\DropInUser\Database\Migrations\InitialSchemaMigration;
use Nexus\DropInUser\Database\PdoConnectionFactory;

require __DIR__ . '/../vendor/autoload.php';

$config = new ModuleConfig(
    dbDsn: getenv('NEXUS_DB_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4',
    dbUser: getenv('NEXUS_DB_USER') ?: 'root',
    dbPassword: getenv('NEXUS_DB_PASS') ?: '',
    fromEmail: 'noreply@example.com',
    fromName: 'Nexus User Module'
);

$pdo = PdoConnectionFactory::create($config->dbDsn, $config->dbUser, $config->dbPassword);

$runner = new MigrationRunner();
$runner->run($pdo, [
    new InitialSchemaMigration(),
    new AddUserProfileFieldsMigration(),
    new AddProfileFieldDefinitionsMigration(),
    new AddAdminVisibilityToProfileFieldDefinitionsMigration(),
]);

echo "Migrations complete.\n";
