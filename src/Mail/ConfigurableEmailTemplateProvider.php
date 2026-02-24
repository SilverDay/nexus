<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Mail;

use Nexus\DropInUser\Contract\EmailTemplateProviderInterface;

final class ConfigurableEmailTemplateProvider implements EmailTemplateProviderInterface
{
    /**
     * @param array<string, array<string, string>> $templates
     */
    public function __construct(private readonly array $templates = [])
    {
    }

    public function render(string $templateName, array $context = []): array
    {
        $defaults = $this->defaultTemplates();
        $selected = $this->templates[$templateName] ?? $defaults[$templateName] ?? null;

        if (!is_array($selected)) {
            $selected = [
                'subject' => 'Notification',
                'text' => 'A notification is available.',
            ];
        }

        $subject = isset($selected['subject']) ? (string) $selected['subject'] : 'Notification';
        $text = isset($selected['text']) ? (string) $selected['text'] : 'A notification is available.';

        return [
            'subject' => $this->renderPlaceholders($subject, $context),
            'text' => $this->renderPlaceholders($text, $context),
        ];
    }

    /**
     * @return array<string, array{subject:string, text:string}>
     */
    private function defaultTemplates(): array
    {
        return [
            'verify_email' => [
                'subject' => 'Verify your email',
                'text' => 'Use this token to verify your email: {{token}}',
            ],
        ];
    }

    /**
     * @param array<string, mixed> $context
     */
    private function renderPlaceholders(string $template, array $context): string
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
