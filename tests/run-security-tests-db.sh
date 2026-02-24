#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DB_CONTAINER_NAME="${NEXUS_DB_CONTAINER_NAME:-nexus-mariadb-test}"
DB_PORT="${NEXUS_DB_PORT:-3307}"
DB_NAME="${NEXUS_DB_NAME:-nexus_user}"
DB_USER="${NEXUS_DB_USER:-nexus}"
DB_PASS="${NEXUS_DB_PASS:-nexuspass}"
DB_ROOT_PASSWORD="${NEXUS_DB_ROOT_PASSWORD:-root}"
DB_IMAGE="${NEXUS_DB_IMAGE:-mariadb:11}"

cleanup() {
    docker rm -f "$DB_CONTAINER_NAME" >/dev/null 2>&1 || true
}

if ! command -v docker >/dev/null 2>&1; then
    echo "[security-tests-db] ERROR: docker is required but not found in PATH"
    exit 1
fi

if ! docker ps >/dev/null 2>&1; then
    echo "[security-tests-db] ERROR: docker daemon is not available"
    exit 1
fi

PHP_BIN="${NEXUS_TEST_PHP_BIN:-}"
if [[ -z "$PHP_BIN" ]]; then
    if [[ -x "/usr/bin/php" ]]; then
        PHP_BIN="/usr/bin/php"
    elif command -v php >/dev/null 2>&1; then
        PHP_BIN="$(command -v php)"
    else
        echo "[security-tests-db] ERROR: no PHP binary found"
        exit 1
    fi
fi

if ! "$PHP_BIN" -m | grep -qi '^pdo_mysql$'; then
    echo "[security-tests-db] ERROR: $PHP_BIN does not have pdo_mysql enabled"
    exit 1
fi

if ! "$PHP_BIN" -m | grep -qi '^mbstring$'; then
    echo "[security-tests-db] ERROR: $PHP_BIN does not have mbstring enabled"
    exit 1
fi

trap cleanup EXIT

echo "[security-tests-db] Starting MariaDB container ($DB_IMAGE) on port $DB_PORT"
cleanup
docker run -d \
    --name "$DB_CONTAINER_NAME" \
    -e MARIADB_ROOT_PASSWORD="$DB_ROOT_PASSWORD" \
    -e MARIADB_DATABASE="$DB_NAME" \
    -e MARIADB_USER="$DB_USER" \
    -e MARIADB_PASSWORD="$DB_PASS" \
    -p "$DB_PORT":3306 \
    "$DB_IMAGE" >/dev/null

echo "[security-tests-db] Waiting for MariaDB readiness"
READY=0
for _ in $(seq 1 90); do
    if "$PHP_BIN" -r "new PDO('mysql:host=127.0.0.1;port=${DB_PORT};dbname=${DB_NAME};charset=utf8mb4','${DB_USER}','${DB_PASS}',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [[ "$READY" -ne 1 ]]; then
    echo "[security-tests-db] ERROR: MariaDB did not become ready in time"
    docker logs "$DB_CONTAINER_NAME" | tail -n 120 || true
    exit 1
fi

echo "[security-tests-db] Running full security test suite with DB integration"
SECURITY_TEST_SCRIPT="${NEXUS_SECURITY_TEST_SCRIPT:-$ROOT_DIR/tests/run-security-tests.sh}"
if [[ "$SECURITY_TEST_SCRIPT" != /* ]]; then
    SECURITY_TEST_SCRIPT="$ROOT_DIR/$SECURITY_TEST_SCRIPT"
fi

if [[ ! -f "$SECURITY_TEST_SCRIPT" ]]; then
    echo "[security-tests-db] ERROR: security test script not found: $SECURITY_TEST_SCRIPT"
    exit 1
fi

echo "[security-tests-db] Applying migrations"
PATH="$(dirname "$PHP_BIN"):$PATH" \
NEXUS_DB_DSN="mysql:host=127.0.0.1;port=${DB_PORT};dbname=${DB_NAME};charset=utf8mb4" \
NEXUS_DB_USER="$DB_USER" \
NEXUS_DB_PASS="$DB_PASS" \
"$PHP_BIN" "$ROOT_DIR/migrations/run.php" >/dev/null

PATH="$(dirname "$PHP_BIN"):$PATH" \
NEXUS_DB_DSN="mysql:host=127.0.0.1;port=${DB_PORT};dbname=${DB_NAME};charset=utf8mb4" \
NEXUS_DB_USER="$DB_USER" \
NEXUS_DB_PASS="$DB_PASS" \
bash "$SECURITY_TEST_SCRIPT"

echo "[security-tests-db] Passed"
