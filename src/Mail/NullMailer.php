<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Mail;

use Nexus\DropInUser\Contract\MailerInterface;

final class NullMailer implements MailerInterface
{
    public function send(string $toEmail, string $subject, string $textBody): void
    {
    }
}
