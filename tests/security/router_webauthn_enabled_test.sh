#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${NEXUS_TEST_PORT:-18081}"
BASE_URL="http://127.0.0.1:${PORT}"
COOKIE_JAR="$(mktemp)"
LOGIN_PAGE="$(mktemp)"
REGISTER_BEGIN_RESP="$(mktemp)"
AUTH_BEGIN_RESP="$(mktemp)"
SERVER_LOG="$(mktemp)"

cleanup() {
  rm -f "$COOKIE_JAR" "$LOGIN_PAGE" "$REGISTER_BEGIN_RESP" "$AUTH_BEGIN_RESP" "$SERVER_LOG"
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if ! php -m | grep -qi '^pdo_mysql$'; then
  echo "[router-webauthn] Skipped (pdo_mysql extension not available)"
  exit 0
fi

if ! php -r 'new PDO(getenv("NEXUS_DB_DSN") ?: "mysql:host=127.0.0.1;port=3306;dbname=nexus_user;charset=utf8mb4", getenv("NEXUS_DB_USER") ?: "root", getenv("NEXUS_DB_PASS") ?: "", [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);' >/dev/null 2>&1; then
  echo "[router-webauthn] Skipped (database unavailable)"
  exit 0
fi

assert_contains() {
  local file="$1"
  local needle="$2"

  if ! grep -q "$needle" "$file"; then
    echo "Expected response to contain: $needle"
    cat "$file"
    exit 1
  fi
}

echo "[router-webauthn] Running migrations"
php "$ROOT_DIR/migrations/run.php" >/dev/null

echo "[router-webauthn] Starting demo server at ${BASE_URL} with WebAuthn validator enabled"
NEXUS_PASSKEY_WEBAUTHN_ENABLED=1 php -S "127.0.0.1:${PORT}" "$ROOT_DIR/examples/minimal_router.php" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  sleep 1
  if curl -fsS "$BASE_URL/ui/login" >/dev/null 2>&1; then
    break
  fi
done

if ! curl -fsS "$BASE_URL/ui/login" >/dev/null 2>&1; then
  echo "[router-webauthn] Demo server failed to start"
  cat "$SERVER_LOG"
  exit 1
fi

TEST_SUFFIX="$(date +%s)$RANDOM"
USERNAME="webauthn_user_${TEST_SUFFIX}"
EMAIL="webauthn_${TEST_SUFFIX}@example.com"
PASSWORD='CorrectHorseBatteryStaple!123'

echo "[router-webauthn] Registering test user"
curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/register" \
  --data-urlencode "username=${USERNAME}" \
  --data-urlencode "email=${EMAIL}" \
  --data-urlencode "realname=WebAuthn Test" \
  --data-urlencode "password=${PASSWORD}" >/dev/null

echo "[router-webauthn] Fetching login page for CSRF token"
curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL/ui/login" >"$LOGIN_PAGE"
CSRF_TOKEN="$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$LOGIN_PAGE" | head -n1)"

if [[ -z "$CSRF_TOKEN" ]]; then
  echo "[router-webauthn] Failed to parse CSRF token"
  cat "$LOGIN_PAGE"
  exit 1
fi

echo "[router-webauthn] Logging in test user"
curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/ui/login" \
  --data-urlencode "csrf_token=${CSRF_TOKEN}" \
  --data-urlencode "identifier=${USERNAME}" \
  --data-urlencode "password=${PASSWORD}" >/dev/null

echo "[router-webauthn] Verifying /passkeys/register/begin returns non-null options"
STATUS_REGISTER_BEGIN="$(curl -sS -o "$REGISTER_BEGIN_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -X POST "$BASE_URL/passkeys/register/begin")"

if [[ "$STATUS_REGISTER_BEGIN" != "200" ]]; then
  echo "Expected /passkeys/register/begin with WebAuthn enabled to return 200, got $STATUS_REGISTER_BEGIN"
  cat "$REGISTER_BEGIN_RESP"
  exit 1
fi

assert_contains "$REGISTER_BEGIN_RESP" '"ok":true'
assert_contains "$REGISTER_BEGIN_RESP" '"options":'
assert_contains "$REGISTER_BEGIN_RESP" '"challenge"'

echo "[router-webauthn] Verifying /passkeys/authenticate/begin returns non-null options"
STATUS_AUTH_BEGIN="$(curl -sS -o "$AUTH_BEGIN_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -X POST "$BASE_URL/passkeys/authenticate/begin")"

if [[ "$STATUS_AUTH_BEGIN" != "200" ]]; then
  echo "Expected /passkeys/authenticate/begin with WebAuthn enabled to return 200, got $STATUS_AUTH_BEGIN"
  cat "$AUTH_BEGIN_RESP"
  exit 1
fi

assert_contains "$AUTH_BEGIN_RESP" '"ok":true'
assert_contains "$AUTH_BEGIN_RESP" '"options":'
assert_contains "$AUTH_BEGIN_RESP" '"challenge"'

echo "[router-webauthn] Passed"
