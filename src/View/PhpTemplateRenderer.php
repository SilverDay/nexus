<?php

declare(strict_types=1);

namespace Nexus\DropInUser\View;

use Nexus\DropInUser\Contract\TemplateRendererInterface;

final class PhpTemplateRenderer implements TemplateRendererInterface
{
    public function __construct(private readonly TemplateLoader $loader)
    {
    }

    public function render(string $templateName, array $data = [], ?string $locale = null): string
    {
        $template = $this->loader->resolve($templateName, $locale);
        if (!is_string($template)) {
            throw new \RuntimeException('Template not found: ' . $templateName);
        }

        $escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        ob_start();
        try {
            extract($data, EXTR_SKIP);
            $e = $escape;
            include $template;
            $output = ob_get_clean();

            return is_string($output) ? $output : '';
        } catch (\Throwable $exception) {
            ob_end_clean();
            throw $exception;
        }
    }
}
