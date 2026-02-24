<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Mail;

use Nexus\DropInUser\Contract\MailerInterface;

final class PhpMailMailer implements MailerInterface
{
    public function __construct(
        private readonly string $fromEmail,
        private readonly string $fromName,
    ) {
    }

    public function send(string $toEmail, string $subject, string $textBody): void
    {
        if (!$this->isValidEmail($toEmail) || !$this->isValidEmail($this->fromEmail)) {
            throw new \InvalidArgumentException('Invalid mail address.');
        }

        $safeFromName = $this->sanitizeHeaderValue($this->fromName);
        $safeSubject = $this->sanitizeHeaderValue($subject);

        $headers = [
            sprintf('From: %s <%s>', $safeFromName, $this->fromEmail),
            'Content-Type: text/plain; charset=UTF-8',
        ];

        $sent = mail($toEmail, $safeSubject, $textBody, implode("\r\n", $headers));
        if ($sent !== true) {
            throw new \RuntimeException('Failed to send email.');
        }
    }

    private function isValidEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    private function sanitizeHeaderValue(string $value): string
    {
        if (str_contains($value, "\r") || str_contains($value, "\n")) {
            throw new \InvalidArgumentException('Invalid mail header value.');
        }

        $sanitized = trim($value);
        if ($sanitized === '') {
            throw new \InvalidArgumentException('Invalid mail header value.');
        }

        return mb_substr($sanitized, 0, 160);
    }
}
