<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Mail;

use Nexus\DropInUser\Config\ModuleConfig;
use Nexus\DropInUser\Contract\MailerInterface;
use RuntimeException;

final class MailerFactory
{
    /**
     * @param array<string, mixed> $settings
     */
    public static function create(ModuleConfig $config, array $settings = []): MailerInterface
    {
        $transport = strtolower(trim((string) ($settings['mail_transport'] ?? 'null')));

        if ($transport === '' || $transport === 'null' || $transport === 'none') {
            return new NullMailer();
        }

        if ($transport === 'php') {
            return new PhpMailMailer($config->fromEmail, $config->fromName);
        }

        if ($transport === 'smtp') {
            $host = trim((string) ($settings['smtp_host'] ?? ''));
            if ($host === '') {
                throw new RuntimeException('SMTP transport requires "smtp_host".');
            }

            return new SmtpMailer(
                host: $host,
                port: max(1, (int) ($settings['smtp_port'] ?? 587)),
                fromEmail: $config->fromEmail,
                fromName: $config->fromName,
                username: trim((string) ($settings['smtp_username'] ?? '')),
                password: (string) ($settings['smtp_password'] ?? ''),
                encryption: strtolower(trim((string) ($settings['smtp_encryption'] ?? 'tls'))),
                timeoutSeconds: max(3, (int) ($settings['smtp_timeout_seconds'] ?? 10)),
            );
        }

        throw new RuntimeException('Unsupported mail transport: ' . $transport);
    }
}
