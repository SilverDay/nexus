<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Mail;

use Nexus\DropInUser\Contract\EmailTemplateProviderInterface;

final class FileEmailTemplateProvider implements EmailTemplateProviderInterface
{
    /**
     * @param list<string> $templateRoots
     */
    public function __construct(
        private readonly array $templateRoots,
        private readonly string $defaultLocale = 'en',
        private readonly ?EmailTemplateProviderInterface $fallbackProvider = null,
        private readonly PreformattedEmailTemplateEngine $templateEngine = new PreformattedEmailTemplateEngine(),
    ) {
    }

    public function render(string $templateName, array $context = []): array
    {
        $locale = $this->resolveLocale($context);
        $paths = $this->resolveTemplatePaths($templateName, $locale);

        if ($paths === null) {
            return $this->fallback($templateName, $context);
        }

        $template = $this->loadTemplate($paths['subject'], $paths['body']);
        if ($template === null) {
            return $this->fallback($templateName, $context);
        }

        return [
            'subject' => $this->templateEngine->render($template['subject'], $context),
            'text' => $this->templateEngine->render($template['text'], $context),
        ];
    }

    /**
     * @param array<string, mixed> $context
     */
    private function resolveLocale(array $context): string
    {
        if (isset($context['locale']) && is_string($context['locale']) && trim($context['locale']) !== '') {
            return $this->normalizeLocale($context['locale']);
        }

        return $this->normalizeLocale($this->defaultLocale);
    }

    private function normalizeLocale(string $locale): string
    {
        $normalized = strtolower(trim($locale));
        if ($normalized === '') {
            return 'en';
        }

        return str_replace('_', '-', $normalized);
    }

    /**
     * @return array{subject:string, body:string}|null
     */
    private function resolveTemplatePaths(string $templateName, string $locale): ?array
    {
        $candidateLocales = [$locale];
        $langOnly = explode('-', $locale)[0] ?? '';
        if ($langOnly !== '' && $langOnly !== $locale) {
            $candidateLocales[] = $langOnly;
        }

        if (!in_array('en', $candidateLocales, true)) {
            $candidateLocales[] = 'en';
        }

        foreach ($this->templateRoots as $root) {
            foreach ($candidateLocales as $candidateLocale) {
                $basePath = rtrim($root, '/\\') . DIRECTORY_SEPARATOR . $candidateLocale . DIRECTORY_SEPARATOR . $templateName;
                $subjectPath = $basePath . '.subject.txt';
                $bodyPath = $basePath . '.body.txt';

                if (is_file($subjectPath) && is_file($bodyPath)) {
                    return [
                        'subject' => $subjectPath,
                        'body' => $bodyPath,
                    ];
                }
            }
        }

        return null;
    }

    /**
     * @return array{subject:string, text:string}|null
     */
    private function loadTemplate(string $subjectPath, string $bodyPath): ?array
    {
        $subject = @file_get_contents($subjectPath);
        $text = @file_get_contents($bodyPath);
        if (!is_string($subject) || !is_string($text)) {
            return null;
        }

        $subject = trim($subject);
        $text = trim($text);

        return [
            'subject' => $subject,
            'text' => $text,
        ];
    }

    /**
     * @param array<string, mixed> $context
     */
    private function fallback(string $templateName, array $context): array
    {
        if ($this->fallbackProvider !== null) {
            return $this->fallbackProvider->render($templateName, $context);
        }

        return [
            'subject' => 'Notification',
            'text' => 'A notification is available.',
        ];
    }
}
