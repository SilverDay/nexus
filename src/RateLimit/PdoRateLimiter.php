<?php

declare(strict_types=1);

namespace Nexus\DropInUser\RateLimit;

use PDO;

final class PdoRateLimiter implements RateLimiter
{
    private const CLEANUP_SAMPLE_RATE = 100;

    public function __construct(private readonly PDO $pdo)
    {
    }

    public function allow(string $bucket, int $limit, int $windowSeconds): bool
    {
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $windowStart = $now->sub(new \DateInterval(sprintf('PT%dS', $windowSeconds)));
        $lockName = 'nexus_rate_limit_' . hash('sha256', $bucket);

        if (!$this->acquireLock($lockName)) {
            return false;
        }

        try {
            if (random_int(1, self::CLEANUP_SAMPLE_RATE) === 1) {
                $cleanup = $this->pdo->prepare('DELETE FROM rate_limit_hits WHERE created_at < :window_start');
                $cleanup->execute(['window_start' => $windowStart->format('Y-m-d H:i:s')]);
            }

            $countStmt = $this->pdo->prepare('SELECT COUNT(*) FROM rate_limit_hits WHERE bucket = :bucket AND created_at >= :window_start');
            $countStmt->execute([
                'bucket' => $bucket,
                'window_start' => $windowStart->format('Y-m-d H:i:s'),
            ]);

            $count = (int) $countStmt->fetchColumn();
            if ($count >= $limit) {
                return false;
            }

            $insert = $this->pdo->prepare('INSERT INTO rate_limit_hits (bucket, created_at) VALUES (:bucket, :created_at)');
            $insert->execute([
                'bucket' => $bucket,
                'created_at' => $now->format('Y-m-d H:i:s'),
            ]);

            return true;
        } finally {
            $this->releaseLock($lockName);
        }
    }

    private function acquireLock(string $lockName): bool
    {
        $stmt = $this->pdo->prepare('SELECT GET_LOCK(:lock_name, 2)');
        $stmt->execute(['lock_name' => $lockName]);

        return (int) $stmt->fetchColumn() === 1;
    }

    private function releaseLock(string $lockName): void
    {
        $stmt = $this->pdo->prepare('SELECT RELEASE_LOCK(:lock_name)');
        $stmt->execute(['lock_name' => $lockName]);
    }
}
