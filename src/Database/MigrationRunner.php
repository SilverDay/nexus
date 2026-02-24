<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database;

use PDO;

final class MigrationRunner
{
    /**
     * @param list<MigrationInterface> $migrations
     */
    public function run(PDO $pdo, array $migrations): void
    {
        $this->ensureSchemaVersionTable($pdo);

        usort(
            $migrations,
            static fn (MigrationInterface $a, MigrationInterface $b): int => strcmp($a->version(), $b->version())
        );

        foreach ($migrations as $migration) {
            if ($this->isApplied($pdo, $migration->version())) {
                continue;
            }

            $pdo->beginTransaction();
            try {
                $migration->up($pdo);
                $this->markApplied($pdo, $migration);
                $pdo->commit();
            } catch (\Throwable $exception) {
                $pdo->rollBack();
                throw $exception;
            }
        }
    }

    private function ensureSchemaVersionTable(PDO $pdo): void
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS schema_versions (
                version VARCHAR(64) PRIMARY KEY,
                description VARCHAR(255) NOT NULL,
                applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
    }

    private function isApplied(PDO $pdo, string $version): bool
    {
        $stmt = $pdo->prepare('SELECT 1 FROM schema_versions WHERE version = :version LIMIT 1');
        $stmt->execute(['version' => $version]);

        return (bool) $stmt->fetchColumn();
    }

    private function markApplied(PDO $pdo, MigrationInterface $migration): void
    {
        $stmt = $pdo->prepare(
            'INSERT INTO schema_versions (version, description) VALUES (:version, :description)'
        );
        $stmt->execute([
            'version' => $migration->version(),
            'description' => $migration->description(),
        ]);
    }
}
