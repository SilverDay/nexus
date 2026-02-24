<?php

declare(strict_types=1);

use Nexus\DropInUser\Profile\ConfigurableProfileFieldPolicy;

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

function assert_contains_string(array $haystack, string $needle, string $message): void
{
    foreach ($haystack as $item) {
        if (is_string($item) && str_contains($item, $needle)) {
            return;
        }
    }

    fwrite(STDERR, "Assertion failed: {$message}\n");
    exit(1);
}

$policy = new ConfigurableProfileFieldPolicy([
    'alias' => [
        'required' => false,
        'max_length' => 999999,
        'pattern' => '/^[a-z]{3,8}$/',
        'user_editable' => true,
        'user_visible' => true,
    ],
    'unsafe_pattern' => [
        'required' => false,
        'pattern' => '/([a-z]+/',
        'user_editable' => true,
        'user_visible' => true,
    ],
]);

$tooLong = str_repeat('a', 5001);
$resultTooLong = $policy->validateForProfileUpdate(['alias' => $tooLong]);
assert_true($resultTooLong['ok'] === false, 'Length above absolute max should fail validation.');
assert_contains_string($resultTooLong['errors'], 'Field too long: alias', 'Expected field-too-long validation error.');

$invalidPatternResult = $policy->validateForProfileUpdate(['unsafe_pattern' => 'abc']);
assert_true($invalidPatternResult['ok'] === false, 'Malformed regex pattern should fail validation safely.');
assert_contains_string($invalidPatternResult['errors'], 'Invalid format: unsafe_pattern', 'Expected invalid format error for malformed regex.');

$validResult = $policy->validateForProfileUpdate(['alias' => 'secureid']);
assert_true($validResult['ok'] === true, 'Valid profile field value should pass validation.');
assert_true(($validResult['fields']['alias'] ?? null) === 'secureid', 'Valid value should be retained in sanitized fields.');

echo "[profile-field-policy-test] Passed\n";
