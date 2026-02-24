#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${NEXUS_TEST_PORT:-18080}"
BASE_URL="http://127.0.0.1:${PORT}"
COOKIE_JAR="$(mktemp)"
LOGIN_PAGE="$(mktemp)"
RESP_NO_CSRF="$(mktemp)"
RESP_WITH_CSRF="$(mktemp)"
RESET_RESP="$(mktemp)"
SERVER_LOG="$(mktemp)"

cleanup() {
  rm -f "$COOKIE_JAR" "$LOGIN_PAGE" "$RESP_NO_CSRF" "$RESP_WITH_CSRF" "$RESET_RESP" "$SERVER_LOG"
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if ! php -m | grep -qi '^pdo_mysql$'; then
  echo "[router-security] SKIP: pdo_mysql extension is not available"
  exit 0
fi

DB_DSN="${NEXUS_DB_DSN:-mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4}"
DB_USER="${NEXUS_DB_USER:-root}"
DB_PASS="${NEXUS_DB_PASS:-}"

if ! php -r 'new PDO(getenv("NEXUS_DB_DSN") ?: "mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4", getenv("NEXUS_DB_USER") ?: "root", getenv("NEXUS_DB_PASS") ?: "", [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);' >/dev/null 2>&1; then
  echo "[router-security] SKIP: cannot connect to MariaDB/MySQL with current NEXUS_DB_* settings"
  echo "[router-security]      DSN=${DB_DSN} USER=${DB_USER}"
  exit 0
fi

assert_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -q "$expected" "$file"; then
    echo "Assertion failed: expected '$expected' in $file"
    echo "--- file content ---"
    cat "$file"
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -q "$unexpected" "$file"; then
    echo "Assertion failed: did not expect '$unexpected' in $file"
    echo "--- file content ---"
    cat "$file"
    exit 1
  fi
}

echo "[router-security] Running migrations"
php "$ROOT_DIR/migrations/run.php" >/dev/null

echo "[router-security] Starting demo server at ${BASE_URL}"
php -S "127.0.0.1:${PORT}" "$ROOT_DIR/examples/minimal_router.php" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS "$BASE_URL/ui/login" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -fsS "$BASE_URL/ui/login" >/dev/null 2>&1; then
  echo "Server failed to start. Logs:"
  cat "$SERVER_LOG"
  exit 1
fi

TEST_SUFFIX="$(date +%s)$RANDOM"
USERNAME="security_user_${TEST_SUFFIX}"
EMAIL="security_${TEST_SUFFIX}@example.com"
PASSWORD='CorrectHorseBatteryStaple!123'

echo "[router-security] Registering test user"
curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/register" \
  --data-urlencode "username=${USERNAME}" \
  --data-urlencode "email=${EMAIL}" \
  --data-urlencode "realname=Security Test User" \
  --data-urlencode "password=${PASSWORD}" >/dev/null

echo "[router-security] Fetching login page for CSRF token"
curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL/ui/login" >"$LOGIN_PAGE"
CSRF_TOKEN="$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$LOGIN_PAGE" | head -n1)"

if [[ -z "$CSRF_TOKEN" ]]; then
  echo "Failed to parse CSRF token from login page"
  cat "$LOGIN_PAGE"
  exit 1
fi

echo "[router-security] Logging in test user"
curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/ui/login" \
  --data-urlencode "csrf_token=${CSRF_TOKEN}" \
  --data-urlencode "identifier=${USERNAME}" \
  --data-urlencode "password=${PASSWORD}" >/dev/null

echo "[router-security] Verifying JSON /profile rejects missing CSRF"
STATUS_NO_CSRF="$(curl -sS -o "$RESP_NO_CSRF" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/profile" \
  --data-urlencode "realname=Security Test User")"

if [[ "$STATUS_NO_CSRF" != "400" ]]; then
  echo "Expected /profile without CSRF to return 400, got $STATUS_NO_CSRF"
  cat "$RESP_NO_CSRF"
  exit 1
fi
assert_contains "$RESP_NO_CSRF" '"ok":false'

echo "[router-security] Verifying JSON /profile accepts valid CSRF header"
STATUS_WITH_CSRF="$(curl -sS -o "$RESP_WITH_CSRF" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -X POST "$BASE_URL/profile" \
  --data-urlencode "realname=Security Test User Updated")"

if [[ "$STATUS_WITH_CSRF" != "200" ]]; then
  echo "Expected /profile with CSRF to return 200, got $STATUS_WITH_CSRF"
  cat "$RESP_WITH_CSRF"
  exit 1
fi
assert_contains "$RESP_WITH_CSRF" '"ok":true'

echo "[router-security] Verifying reset request does not expose demo_token by default"
STATUS_RESET="$(curl -sS -o "$RESET_RESP" -w "%{http_code}" \
  -X POST "$BASE_URL/password-reset/request" \
  --data-urlencode "identifier=${EMAIL}")"

if [[ "$STATUS_RESET" != "200" ]]; then
  echo "Expected /password-reset/request to return 200, got $STATUS_RESET"
  cat "$RESET_RESP"
  exit 1
fi
assert_contains "$RESET_RESP" '"ok":true'
assert_not_contains "$RESET_RESP" 'demo_token'

echo "[router-security] Passed"
