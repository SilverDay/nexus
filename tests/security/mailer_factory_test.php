<?php

declare(strict_types=1);

use Nexus\DropInUser\Config\ModuleConfig;
use Nexus\DropInUser\Mail\MailerFactory;
use Nexus\DropInUser\Mail\NullMailer;
use Nexus\DropInUser\Mail\PhpMailMailer;
use Nexus\DropInUser\Mail\SmtpMailer;

require __DIR__ . '/../../vendor/autoload.php';

$config = new ModuleConfig(
    dbDsn: 'mysql:host=localhost;port=3306;dbname=test;charset=utf8mb4',
    dbUser: 'root',
    dbPassword: '',
    fromEmail: 'noreply@example.com',
    fromName: 'Nexus User Module',
);

$nullMailer = MailerFactory::create($config, ['mail_transport' => 'null']);
assert($nullMailer instanceof NullMailer);

$phpMailer = MailerFactory::create($config, ['mail_transport' => 'php']);
assert($phpMailer instanceof PhpMailMailer);

$smtpMailer = MailerFactory::create($config, [
    'mail_transport' => 'smtp',
    'smtp_host' => 'smtp.example.com',
    'smtp_port' => 587,
    'smtp_username' => 'smtp-user',
    'smtp_password' => 'smtp-pass',
    'smtp_encryption' => 'tls',
]);
assert($smtpMailer instanceof SmtpMailer);

$threw = false;
try {
    MailerFactory::create($config, ['mail_transport' => 'smtp']);
} catch (RuntimeException) {
    $threw = true;
}
assert($threw === true);

echo "mailer_factory_test: ok\n";
