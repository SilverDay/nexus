<?php

declare(strict_types=1);

use Nexus\DropInUser\Mail\PhpMailMailer;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * @param bool $condition
 */
function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "Assertion failed: {$message}\n");
        exit(1);
    }
}

function assert_invalid_argument(callable $callable, string $message): void
{
    try {
        $callable();
    } catch (InvalidArgumentException) {
        return;
    } catch (Throwable $exception) {
        fwrite(STDERR, "Assertion failed: {$message} (threw unexpected " . $exception::class . ")\n");
        exit(1);
    }

    fwrite(STDERR, "Assertion failed: {$message} (did not throw InvalidArgumentException)\n");
    exit(1);
}

$mailerWithInjectedFrom = new PhpMailMailer('noreply@example.com', "Nexus\r\nBcc: injected@example.com");
assert_invalid_argument(
    static fn () => $mailerWithInjectedFrom->send('user@example.com', 'Subject', 'Body'),
    'From name header injection must be rejected.'
);

$mailer = new PhpMailMailer('noreply@example.com', 'Nexus Mailer');
assert_invalid_argument(
    static fn () => $mailer->send('invalid-email', 'Subject', 'Body'),
    'Invalid recipient address must be rejected.'
);

assert_invalid_argument(
    static fn () => $mailer->send('user@example.com', "Hello\r\nBcc: evil@example.com", 'Body'),
    'Subject header injection must be rejected.'
);

assert_true(true, 'Mailer rejection tests passed.');
echo "[php-mail-mailer-test] Passed\n";
