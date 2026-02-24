<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Mail;

use Nexus\DropInUser\Contract\MailerInterface;
use RuntimeException;

final class SmtpMailer implements MailerInterface
{
    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $fromEmail,
        private readonly string $fromName,
        private readonly string $username = '',
        private readonly string $password = '',
        private readonly string $encryption = 'tls',
        private readonly int $timeoutSeconds = 10,
    ) {
    }

    public function send(string $toEmail, string $subject, string $textBody): void
    {
        if (!$this->isValidEmail($toEmail) || !$this->isValidEmail($this->fromEmail)) {
            throw new \InvalidArgumentException('Invalid mail address.');
        }

        $safeSubject = $this->sanitizeHeaderValue($subject);
        $safeFromName = $this->sanitizeHeaderValue($this->fromName);

        $remoteHost = $this->encryption === 'ssl'
            ? 'ssl://' . $this->host
            : $this->host;

        $socket = @stream_socket_client(
            $remoteHost . ':' . $this->port,
            $errorCode,
            $errorMessage,
            $this->timeoutSeconds
        );

        if (!is_resource($socket)) {
            throw new RuntimeException('SMTP connection failed: ' . $errorMessage . ' (' . $errorCode . ')');
        }

        stream_set_timeout($socket, $this->timeoutSeconds);

        try {
            $this->expectCode($socket, [220]);

            $hostname = gethostname();
            if (!is_string($hostname) || trim($hostname) === '') {
                $hostname = 'localhost';
            }

            $this->command($socket, 'EHLO ' . $hostname, [250]);

            if ($this->encryption === 'tls') {
                $this->command($socket, 'STARTTLS', [220]);
                $tlsEnabled = stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
                if ($tlsEnabled !== true) {
                    throw new RuntimeException('Unable to enable STARTTLS.');
                }
                $this->command($socket, 'EHLO ' . $hostname, [250]);
            }

            if ($this->username !== '') {
                $this->command($socket, 'AUTH LOGIN', [334]);
                $this->command($socket, base64_encode($this->username), [334]);
                $this->command($socket, base64_encode($this->password), [235]);
            }

            $this->command($socket, 'MAIL FROM:<' . $this->fromEmail . '>', [250]);
            $this->command($socket, 'RCPT TO:<' . $toEmail . '>', [250, 251]);
            $this->command($socket, 'DATA', [354]);

            $headers = [
                sprintf('From: %s <%s>', $safeFromName, $this->fromEmail),
                'To: ' . $toEmail,
                'Subject: ' . $safeSubject,
                'MIME-Version: 1.0',
                'Content-Type: text/plain; charset=UTF-8',
            ];

            $dotSafeBody = preg_replace('/^\./m', '..', $textBody) ?? $textBody;
            $payload = implode("\r\n", $headers) . "\r\n\r\n" . $dotSafeBody . "\r\n.";
            $this->command($socket, $payload, [250]);
            $this->command($socket, 'QUIT', [221]);
        } finally {
            fclose($socket);
        }
    }

    /**
     * @param resource $socket
     * @param list<int> $expectedCodes
     */
    private function command($socket, string $command, array $expectedCodes): string
    {
        fwrite($socket, $command . "\r\n");

        return $this->expectCode($socket, $expectedCodes);
    }

    /**
     * @param resource $socket
     * @param list<int> $expectedCodes
     */
    private function expectCode($socket, array $expectedCodes): string
    {
        $response = '';
        while (($line = fgets($socket)) !== false) {
            $response .= $line;

            if (strlen($line) < 4) {
                continue;
            }

            if ($line[3] === ' ') {
                break;
            }
        }

        if ($response === '' || !preg_match('/^(\d{3})/m', $response, $matches)) {
            throw new RuntimeException('Invalid SMTP response.');
        }

        $code = (int) $matches[1];
        if (!in_array($code, $expectedCodes, true)) {
            throw new RuntimeException('Unexpected SMTP response [' . $code . ']: ' . trim($response));
        }

        return $response;
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
