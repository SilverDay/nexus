<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Observability;

use Nexus\DropInUser\Contract\TokenServiceInterface;

final class RequestContext
{
    private const REQUEST_ID_PATTERN = '/^[A-Za-z0-9._-]{8,120}$/';

    private ?string $requestId = null;

    public function __construct(private readonly TokenServiceInterface $tokenService)
    {
    }

    public function requestId(): string
    {
        if ($this->requestId !== null) {
            return $this->requestId;
        }

        $header = $_SERVER['HTTP_X_REQUEST_ID'] ?? null;
        if (is_string($header)) {
            $candidate = substr(trim($header), 0, 120);
            if ($candidate !== '' && preg_match(self::REQUEST_ID_PATTERN, $candidate) === 1) {
                $this->requestId = $candidate;
                return $this->requestId;
            }
        }

        $generated = bin2hex(random_bytes(16));
        if (preg_match(self::REQUEST_ID_PATTERN, $generated) !== 1) {
            $generated = $this->tokenService->hashToken((string) microtime(true) . random_int(1000, 999999));
            $generated = substr($generated, 0, 32);
        }

        $this->requestId = $generated;

        return $this->requestId;
    }

    public function sourceIp(): string
    {
        return isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
            ? $_SERVER['REMOTE_ADDR']
            : '0.0.0.0';
    }

    public function userAgentHash(): string
    {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) && is_string($_SERVER['HTTP_USER_AGENT'])
            ? $_SERVER['HTTP_USER_AGENT']
            : 'unknown';

        return $this->tokenService->hashUserAgent($ua);
    }

    /**
     * @return array{source_ip: string, user_agent_hash: string, request_id: string}
     */
    public function asAuditContext(): array
    {
        return [
            'source_ip' => $this->sourceIp(),
            'user_agent_hash' => $this->userAgentHash(),
            'request_id' => $this->requestId(),
        ];
    }
}
