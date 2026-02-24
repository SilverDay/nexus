<?php

declare(strict_types=1);

use Nexus\DropInUser\Mail\ConfigurableEmailTemplateProvider;

require __DIR__ . '/../../vendor/autoload.php';

$provider = new ConfigurableEmailTemplateProvider([
    'verify_email' => [
        'subject' => 'Verify {{email}}',
        'text' => 'Token: {{token}}',
    ],
]);

$rendered = $provider->render('verify_email', [
    'email' => 'user@example.com',
    'token' => 'abc123',
]);

assert($rendered['subject'] === 'Verify user@example.com');
assert($rendered['text'] === 'Token: abc123');

$defaultRendered = $provider->render('unknown_template', [
    'token' => 'xyz',
]);
assert(isset($defaultRendered['subject'], $defaultRendered['text']));

echo "configurable_email_template_provider_test: ok\n";
