<?php

declare(strict_types=1);

use Nexus\DropInUser\Mail\ConfigurableEmailTemplateProvider;
use Nexus\DropInUser\Mail\FileEmailTemplateProvider;

require __DIR__ . '/../../vendor/autoload.php';

$root = sys_get_temp_dir() . '/nexus_email_tpl_' . bin2hex(random_bytes(6));

if (!mkdir($root . '/en', 0777, true) && !is_dir($root . '/en')) {
    throw new RuntimeException('Unable to create test template directory');
}

if (!mkdir($root . '/de', 0777, true) && !is_dir($root . '/de')) {
    throw new RuntimeException('Unable to create test template directory');
}

file_put_contents(
    $root . '/en/verify_email.subject.txt',
    "Verify account\n"
);

file_put_contents(
    $root . '/en/verify_email.body.txt',
    "Token: {{token}}\n"
);

file_put_contents(
    $root . '/de/verify_email.subject.txt',
    "Konto verifizieren\n"
);

file_put_contents(
    $root . '/de/verify_email.body.txt',
    "Code: {{token}}\n"
);

$fallback = new ConfigurableEmailTemplateProvider([
    'verify_email' => [
        'subject' => 'Fallback subject',
        'text' => 'Fallback token {{token}}',
    ],
]);

$provider = new FileEmailTemplateProvider([$root], 'en', $fallback);

$deRendered = $provider->render('verify_email', [
    'locale' => 'de-DE',
    'token' => 'abc123',
]);

if ($deRendered['subject'] !== 'Konto verifizieren') {
    throw new RuntimeException('Locale-specific subject not loaded from file');
}

if ($deRendered['text'] !== 'Code: abc123') {
    throw new RuntimeException('Locale-specific text placeholders not rendered');
}

$frRendered = $provider->render('verify_email', [
    'locale' => 'fr',
    'token' => 'xyz789',
]);

if ($frRendered['subject'] !== 'Verify account') {
    throw new RuntimeException('EN fallback file not used when locale file missing');
}

if ($frRendered['text'] !== 'Token: xyz789') {
    throw new RuntimeException('EN fallback text placeholders not rendered');
}

$missingRendered = $provider->render('password_reset', [
    'token' => 'r-1',
]);

if ($missingRendered['subject'] !== 'Notification') {
    throw new RuntimeException('Missing template should use fallback provider defaults');
}

echo "file_email_template_provider_test: ok\n";
