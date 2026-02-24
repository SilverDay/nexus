<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database;

use PDO;

interface MigrationInterface
{
    public function version(): string;

    public function description(): string;

    public function up(PDO $pdo): void;
}
