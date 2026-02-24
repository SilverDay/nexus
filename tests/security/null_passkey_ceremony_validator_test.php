<?php

declare(strict_types=1);

use Nexus\DropInUser\Service\NullPasskeyCeremonyValidator;

require __DIR__ . '/../../vendor/autoload.php';

$validator = new NullPasskeyCeremonyValidator();

assert($validator->createRegistrationOptions(['challenge' => 'abc']) === []);
assert($validator->validateRegistrationResponse(['challenge' => 'abc'], ['id' => 'cred']) === null);
assert($validator->createAuthenticationOptions(['challenge' => 'xyz']) === []);
assert($validator->validateAuthenticationResponse(['challenge' => 'xyz'], ['id' => 'cred']) === null);

echo "null_passkey_ceremony_validator_test: ok\n";
