<?php

declare(strict_types=1);

use Nexus\DropInUser\Service\NullPasskeyService;

require __DIR__ . '/../../vendor/autoload.php';

$service = new NullPasskeyService();

assert($service->beginRegistration(123) === []);
assert($service->finishRegistration(123, ['id' => 'credential']) === false);
assert($service->beginAuthentication(123) === []);
assert($service->finishAuthentication(['id' => 'assertion']) === null);

echo "passkey_null_service_test: ok\n";
