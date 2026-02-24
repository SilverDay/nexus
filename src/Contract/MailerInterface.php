<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface MailerInterface
{
    public function send(string $toEmail, string $subject, string $textBody): void;
}
