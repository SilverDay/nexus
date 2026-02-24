<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Oidc;

use Nexus\DropInUser\Contract\OidcProviderInterface;

final class GoogleOidcProvider implements OidcProviderInterface
{
    private const AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
    private const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
    private const USERINFO_ENDPOINT = 'https://openidconnect.googleapis.com/v1/userinfo';

    public function __construct(
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly string $redirectUri,
    ) {
    }

    public function authorizationUrl(string $state, string $nonce): string
    {
        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state,
            'nonce' => $nonce,
            'prompt' => 'select_account',
        ], '', '&', PHP_QUERY_RFC3986);

        return self::AUTHORIZATION_ENDPOINT . '?' . $query;
    }

    public function exchangeCode(string $code): array
    {
        return $this->requestJson(
            'POST',
            self::TOKEN_ENDPOINT,
            [
                'code' => $code,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'redirect_uri' => $this->redirectUri,
                'grant_type' => 'authorization_code',
            ]
        );
    }

    public function fetchUserProfile(array $tokenSet): array
    {
        $accessToken = isset($tokenSet['access_token']) ? trim((string) $tokenSet['access_token']) : '';
        if ($accessToken === '') {
            throw new \RuntimeException('OIDC token exchange did not return an access token.');
        }

        return $this->requestJson(
            'GET',
            self::USERINFO_ENDPOINT,
            null,
            [
                'Authorization: Bearer ' . $accessToken,
            ]
        );
    }

    /**
     * @param array<string, string>|null $formData
     * @param list<string> $headers
     * @return array<string, mixed>
     */
    private function requestJson(string $method, string $url, ?array $formData = null, array $headers = []): array
    {
        $requestHeaders = $headers;
        $requestHeaders[] = 'Accept: application/json';

        $options = [
            'http' => [
                'method' => $method,
                'timeout' => 10,
                'ignore_errors' => true,
                'header' => implode("\r\n", $requestHeaders),
            ],
        ];

        if ($formData !== null) {
            $options['http']['header'] .= "\r\nContent-Type: application/x-www-form-urlencoded";
            $options['http']['content'] = http_build_query($formData, '', '&', PHP_QUERY_RFC3986);
        }

        $context = stream_context_create($options);
        $body = @file_get_contents($url, false, $context);

        $responseHeaders = isset($http_response_header) && is_array($http_response_header)
            ? $http_response_header
            : [];

        $statusCode = $this->parseStatusCode($responseHeaders);
        if (!is_string($body) || $statusCode < 200 || $statusCode >= 300) {
            throw new \RuntimeException('OIDC HTTP request failed.');
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('OIDC response was not valid JSON.');
        }

        return $decoded;
    }

    /**
     * @param list<string> $headers
     */
    private function parseStatusCode(array $headers): int
    {
        $statusLine = $headers[0] ?? '';
        if (!is_string($statusLine)) {
            return 0;
        }

        if (preg_match('/\s(\d{3})\s/', $statusLine, $matches) === 1) {
            return (int) $matches[1];
        }

        return 0;
    }
}
