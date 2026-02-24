<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Contract;

interface TemplateRendererInterface
{
    /**
     * @param array<string, mixed> $data
     */
    public function render(string $templateName, array $data = [], ?string $locale = null): string;
}
