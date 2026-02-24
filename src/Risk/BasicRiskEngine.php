<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Risk;

use Nexus\DropInUser\Contract\RiskEngineInterface;

final class BasicRiskEngine implements RiskEngineInterface
{
    public function assess(
        ?array $lastSession,
        string $currentIp,
        string $currentUserAgentHash,
        string $ipBindingMode,
        bool $bindUserAgent,
    ): string {
        if ($lastSession === null) {
            return RiskDecision::ALLOW;
        }

        $lastIp = isset($lastSession['ip_address']) ? (string) $lastSession['ip_address'] : '';
        $lastUaHash = isset($lastSession['ua_hash']) ? (string) $lastSession['ua_hash'] : '';

        $uaMismatch = $bindUserAgent && $lastUaHash !== '' && !hash_equals($lastUaHash, $currentUserAgentHash);
        $ipMismatch = $lastIp !== '' && !hash_equals($lastIp, $currentIp);
        $subnetMismatch = $lastIp !== '' && !$this->sameSubnet($lastIp, $currentIp);

        return match ($ipBindingMode) {
            'off' => $uaMismatch ? RiskDecision::REQUIRE_STEP_UP : RiskDecision::ALLOW,
            'strict' => ($ipMismatch || $uaMismatch) ? RiskDecision::DENY : RiskDecision::ALLOW,
            'subnet' => ($subnetMismatch || $uaMismatch) ? RiskDecision::DENY : RiskDecision::ALLOW,
            'risk-based' => ($ipMismatch || $uaMismatch || $this->isNewDevice($lastUaHash, $currentUserAgentHash))
                ? RiskDecision::REQUIRE_STEP_UP
                : RiskDecision::ALLOW,
            default => RiskDecision::REQUIRE_STEP_UP,
        };
    }

    private function isNewDevice(string $lastUaHash, string $currentUserAgentHash): bool
    {
        if ($lastUaHash === '') {
            return false;
        }

        return !hash_equals($lastUaHash, $currentUserAgentHash);
    }

    private function sameSubnet(string $ipA, string $ipB): bool
    {
        if (filter_var($ipA, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($ipB, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $aParts = explode('.', $ipA);
            $bParts = explode('.', $ipB);

            return count($aParts) === 4
                && count($bParts) === 4
                && $aParts[0] === $bParts[0]
                && $aParts[1] === $bParts[1]
                && $aParts[2] === $bParts[2];
        }

        if (filter_var($ipA, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($ipB, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $aNormalized = inet_ntop(inet_pton($ipA) ?: '');
            $bNormalized = inet_ntop(inet_pton($ipB) ?: '');
            if (!is_string($aNormalized) || !is_string($bNormalized)) {
                return false;
            }

            $aParts = explode(':', $aNormalized);
            $bParts = explode(':', $bNormalized);

            return isset($aParts[0], $aParts[1], $aParts[2], $aParts[3], $bParts[0], $bParts[1], $bParts[2], $bParts[3])
                && $aParts[0] === $bParts[0]
                && $aParts[1] === $bParts[1]
                && $aParts[2] === $bParts[2]
                && $aParts[3] === $bParts[3];
        }

        return false;
    }
}
