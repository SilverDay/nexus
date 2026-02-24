<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Config;

use Nexus\DropInUser\Contract\ProfileFieldPolicyInterface;
use Nexus\DropInUser\Profile\ConfigurableProfileFieldPolicy;

final class ProfileFieldConfig
{
    /**
    * @param array<string, array{required?: bool, max_length?: int, pattern?: string, user_visible?: bool, user_editable?: bool, admin_visible?: bool, label?: string}> $definitions
     */
    public function __construct(private readonly array $definitions)
    {
    }

    public function createPolicy(): ProfileFieldPolicyInterface
    {
        return new ConfigurableProfileFieldPolicy($this->definitions);
    }

    /**
        * @return array<string, array{required?: bool, max_length?: int, pattern?: string, user_visible?: bool, user_editable?: bool, admin_visible?: bool, label?: string}>
     */
    public function definitions(): array
    {
        return $this->definitions;
    }
}
