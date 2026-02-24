<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface EmailTemplateProviderInterface
{
    /**
     * @param array<string, mixed> $context
     * @return array{subject:string, text:string}
     */
    public function render(string $templateName, array $context = []): array;
}
