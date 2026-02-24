<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Security;

use Nexus\DropInUser\Contract\SecurityHeadersInterface;

final class SecurityHeaders implements SecurityHeadersInterface
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(private readonly array $headers = [])
    {
    }

    public function emit(): void
    {
        $defaults = [
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'X-Frame-Options' => 'DENY',
            'Permissions-Policy' => 'camera=(), microphone=(), geolocation=()',
            'Content-Security-Policy' => "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ];

        $finalHeaders = array_merge($defaults, $this->headers);
        foreach ($finalHeaders as $name => $value) {
            header(sprintf('%s: %s', $name, $value));
        }
    }
}
