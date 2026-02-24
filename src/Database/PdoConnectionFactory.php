<?php

declare(strict_types=1);

namespace Nexus\DropInUser\Database;

use PDO;

final class PdoConnectionFactory
{
    public static function create(string $dsn, string $username, string $password): PDO
    {
        return new PDO(
            $dsn,
            $username,
            $password,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
    }
}
