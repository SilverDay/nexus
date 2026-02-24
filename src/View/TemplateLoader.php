<?php

declare(strict_types=1);

namespace Nexus\DropInUser\View;

final class TemplateLoader
{
    /**
     * @param list<string> $templateRoots
     */
    public function __construct(private readonly array $templateRoots)
    {
    }

    public function resolve(string $templateName, ?string $locale = null): ?string
    {
        $candidateLocales = [];
        if (is_string($locale) && $locale !== '') {
            $candidateLocales[] = $locale;
            $langOnly = explode('-', $locale)[0] ?? null;
            if (is_string($langOnly) && $langOnly !== '' && $langOnly !== $locale) {
                $candidateLocales[] = $langOnly;
            }
        }
        $candidateLocales[] = 'en';

        foreach ($this->templateRoots as $root) {
            foreach ($candidateLocales as $candidateLocale) {
                $path = rtrim($root, '/\\') . DIRECTORY_SEPARATOR . $candidateLocale . DIRECTORY_SEPARATOR . $templateName . '.php';
                if (is_file($path)) {
                    return $path;
                }
            }
        }

        return null;
    }
}
