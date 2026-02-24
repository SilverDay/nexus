<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Mail;

final class PreformattedEmailTemplateEngine
{
    /**
     * @param array<string, mixed> $context
     */
    public function render(string $template, array $context): string
    {
        if ($template === '') {
            return '';
        }

        $replacements = [];
        foreach ($context as $key => $value) {
            if (!is_string($key) || $key === '') {
                continue;
            }

            $replacements['{{' . $key . '}}'] = is_scalar($value) ? (string) $value : '';
        }

        if ($replacements === []) {
            return $template;
        }

        return strtr($template, $replacements);
    }
}
