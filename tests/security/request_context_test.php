<?php

declare(strict_types=1);

use Nexus\DropInUser\Observability\RequestContext;
use Nexus\DropInUser\Security\TokenService;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * @param bool $condition
 */
function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "Assertion failed: {$message}\n");
        exit(1);
    }
}

unset($_SERVER['HTTP_X_REQUEST_ID']);
$context = new RequestContext(new TokenService());
$generated = $context->requestId();

assert_true((bool) preg_match('/^[A-Za-z0-9._-]{8,120}$/', $generated), 'Generated request ID must match allowed format.');
assert_true($context->requestId() === $generated, 'Request ID must remain stable for one request context instance.');

$_SERVER['HTTP_X_REQUEST_ID'] = 'valid-Req_123.456';
$contextWithValidHeader = new RequestContext(new TokenService());
assert_true($contextWithValidHeader->requestId() === 'valid-Req_123.456', 'Valid incoming request ID should be preserved.');

$_SERVER['HTTP_X_REQUEST_ID'] = "bad\r\nInjected: header";
$contextWithBadHeader = new RequestContext(new TokenService());
$sanitized = $contextWithBadHeader->requestId();

assert_true($sanitized !== $_SERVER['HTTP_X_REQUEST_ID'], 'Unsafe request ID header should not be used directly.');
assert_true((bool) preg_match('/^[A-Za-z0-9._-]{8,120}$/', $sanitized), 'Fallback request ID must match allowed format.');

echo "[request-context-test] Passed\n";
