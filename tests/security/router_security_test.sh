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
UI_TOTP_PAGE_RESP="$(mktemp)"
UI_TOTP_NO_CSRF_RESP="$(mktemp)"
UI_STEPUP_RESP="$(mktemp)"
RECOVERY_NO_CSRF_RESP="$(mktemp)"
RECOVERY_WITH_CSRF_RESP="$(mktemp)"
UI_RECOVERY_NO_CSRF_RESP="$(mktemp)"
STEPUP_RECOVERY_RESP="$(mktemp)"
PASSKEY_REGISTER_NO_CSRF_RESP="$(mktemp)"
PASSKEY_REGISTER_WITH_CSRF_RESP="$(mktemp)"
PASSKEY_AUTH_NO_CSRF_RESP="$(mktemp)"
PASSKEY_REGISTER_UNAUTH_RESP="$(mktemp)"
PASSKEY_AUTH_FINISH_NO_CSRF_RESP="$(mktemp)"
PASSKEY_LIST_UNAUTH_RESP="$(mktemp)"
PASSKEY_LIST_AUTH_RESP="$(mktemp)"
PASSKEY_REVOKE_NO_CSRF_RESP="$(mktemp)"
UI_PASSKEYS_UNAUTH_RESP="$(mktemp)"
UI_PASSKEYS_AUTH_RESP="$(mktemp)"
UI_PASSKEYS_REVOKE_NO_CSRF_RESP="$(mktemp)"
SESSIONS_LIST_UNAUTH_RESP="$(mktemp)"
SESSIONS_LIST_AUTH_RESP="$(mktemp)"
SESSIONS_REVOKE_NO_CSRF_RESP="$(mktemp)"
SESSIONS_REVOKE_WITH_CSRF_RESP="$(mktemp)"
PROFILE_AFTER_SESSIONS_REVOKE_RESP="$(mktemp)"
UI_SESSIONS_UNAUTH_RESP="$(mktemp)"
UI_SESSIONS_AUTH_RESP="$(mktemp)"
UI_SESSIONS_REVOKE_NO_CSRF_RESP="$(mktemp)"
SERVER_LOG="$(mktemp)"

cleanup() {
  rm -f "$COOKIE_JAR" "$LOGIN_PAGE" "$RESP_NO_CSRF" "$RESP_WITH_CSRF" "$RESET_RESP" "$UI_TOTP_PAGE_RESP" "$UI_TOTP_NO_CSRF_RESP" "$UI_STEPUP_RESP" "$RECOVERY_NO_CSRF_RESP" "$RECOVERY_WITH_CSRF_RESP" "$UI_RECOVERY_NO_CSRF_RESP" "$STEPUP_RECOVERY_RESP" "$PASSKEY_REGISTER_NO_CSRF_RESP" "$PASSKEY_REGISTER_WITH_CSRF_RESP" "$PASSKEY_AUTH_NO_CSRF_RESP" "$PASSKEY_REGISTER_UNAUTH_RESP" "$PASSKEY_AUTH_FINISH_NO_CSRF_RESP" "$PASSKEY_LIST_UNAUTH_RESP" "$PASSKEY_LIST_AUTH_RESP" "$PASSKEY_REVOKE_NO_CSRF_RESP" "$UI_PASSKEYS_UNAUTH_RESP" "$UI_PASSKEYS_AUTH_RESP" "$UI_PASSKEYS_REVOKE_NO_CSRF_RESP" "$SESSIONS_LIST_UNAUTH_RESP" "$SESSIONS_LIST_AUTH_RESP" "$SESSIONS_REVOKE_NO_CSRF_RESP" "$SESSIONS_REVOKE_WITH_CSRF_RESP" "$PROFILE_AFTER_SESSIONS_REVOKE_RESP" "$UI_SESSIONS_UNAUTH_RESP" "$UI_SESSIONS_AUTH_RESP" "$UI_SESSIONS_REVOKE_NO_CSRF_RESP" "$SERVER_LOG"
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
if ! curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/register" \
  --data-urlencode "username=${USERNAME}" \
  --data-urlencode "email=${EMAIL}" \
  --data-urlencode "realname=Security Test User" \
  --data-urlencode "password=${PASSWORD}" >/dev/null; then
  echo "[router-security] Register request failed. Server logs:"
  cat "$SERVER_LOG"
  exit 1
fi

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

echo "[router-security] Verifying JSON /recovery-codes/regenerate rejects missing CSRF"
STATUS_RECOVERY_NO_CSRF="$(curl -sS -o "$RECOVERY_NO_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/recovery-codes/regenerate")"
if [[ "$STATUS_RECOVERY_NO_CSRF" != "400" ]]; then
  echo "Expected /recovery-codes/regenerate without CSRF to return 400, got $STATUS_RECOVERY_NO_CSRF"
  cat "$RECOVERY_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$RECOVERY_NO_CSRF_RESP" '"ok":false'

echo "[router-security] Verifying JSON /recovery-codes/regenerate accepts CSRF header"
STATUS_RECOVERY_WITH_CSRF="$(curl -sS -o "$RECOVERY_WITH_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -X POST "$BASE_URL/recovery-codes/regenerate")"
if [[ "$STATUS_RECOVERY_WITH_CSRF" != "200" ]]; then
  echo "Expected /recovery-codes/regenerate with CSRF to return 200, got $STATUS_RECOVERY_WITH_CSRF"
  cat "$RECOVERY_WITH_CSRF_RESP"
  exit 1
fi
assert_contains "$RECOVERY_WITH_CSRF_RESP" '"ok":'
assert_contains "$RECOVERY_WITH_CSRF_RESP" '"codes":'

echo "[router-security] Verifying JSON /passkeys/register/begin rejects missing CSRF"
STATUS_PASSKEY_REGISTER_NO_CSRF="$(curl -sS -o "$PASSKEY_REGISTER_NO_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/passkeys/register/begin")"
if [[ "$STATUS_PASSKEY_REGISTER_NO_CSRF" != "400" ]]; then
  echo "Expected /passkeys/register/begin without CSRF to return 400, got $STATUS_PASSKEY_REGISTER_NO_CSRF"
  cat "$PASSKEY_REGISTER_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$PASSKEY_REGISTER_NO_CSRF_RESP" '"ok":false'

echo "[router-security] Verifying JSON /passkeys/register/begin enforces authenticated route and current null service response"
STATUS_PASSKEY_REGISTER_WITH_CSRF="$(curl -sS -o "$PASSKEY_REGISTER_WITH_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -X POST "$BASE_URL/passkeys/register/begin")"
if [[ "$STATUS_PASSKEY_REGISTER_WITH_CSRF" != "400" ]]; then
  echo "Expected /passkeys/register/begin with CSRF to return 400 while null service is active, got $STATUS_PASSKEY_REGISTER_WITH_CSRF"
  cat "$PASSKEY_REGISTER_WITH_CSRF_RESP"
  exit 1
fi
assert_contains "$PASSKEY_REGISTER_WITH_CSRF_RESP" 'Passkey registration is currently unavailable'

echo "[router-security] Verifying JSON /passkeys/authenticate/begin rejects missing CSRF"
STATUS_PASSKEY_AUTH_NO_CSRF="$(curl -sS -o "$PASSKEY_AUTH_NO_CSRF_RESP" -w "%{http_code}" \
  -X POST "$BASE_URL/passkeys/authenticate/begin")"
if [[ "$STATUS_PASSKEY_AUTH_NO_CSRF" != "400" ]]; then
  echo "Expected /passkeys/authenticate/begin without CSRF to return 400, got $STATUS_PASSKEY_AUTH_NO_CSRF"
  cat "$PASSKEY_AUTH_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$PASSKEY_AUTH_NO_CSRF_RESP" '"ok":false'

echo "[router-security] Verifying JSON /passkeys/register/begin rejects unauthenticated access"
STATUS_PASSKEY_REGISTER_UNAUTH="$(curl -sS -o "$PASSKEY_REGISTER_UNAUTH_RESP" -w "%{http_code}" \
  -X POST "$BASE_URL/passkeys/register/begin")"
if [[ "$STATUS_PASSKEY_REGISTER_UNAUTH" != "401" ]]; then
  echo "Expected /passkeys/register/begin unauthenticated to return 401, got $STATUS_PASSKEY_REGISTER_UNAUTH"
  cat "$PASSKEY_REGISTER_UNAUTH_RESP"
  exit 1
fi
assert_contains "$PASSKEY_REGISTER_UNAUTH_RESP" '"ok":false'

echo "[router-security] Verifying JSON /passkeys/authenticate/finish rejects missing CSRF"
STATUS_PASSKEY_AUTH_FINISH_NO_CSRF="$(curl -sS -o "$PASSKEY_AUTH_FINISH_NO_CSRF_RESP" -w "%{http_code}" \
  -X POST "$BASE_URL/passkeys/authenticate/finish")"
if [[ "$STATUS_PASSKEY_AUTH_FINISH_NO_CSRF" != "400" ]]; then
  echo "Expected /passkeys/authenticate/finish without CSRF to return 400, got $STATUS_PASSKEY_AUTH_FINISH_NO_CSRF"
  cat "$PASSKEY_AUTH_FINISH_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$PASSKEY_AUTH_FINISH_NO_CSRF_RESP" '"ok":false'

echo "[router-security] Verifying JSON /passkeys/list rejects unauthenticated access"
STATUS_PASSKEY_LIST_UNAUTH="$(curl -sS -o "$PASSKEY_LIST_UNAUTH_RESP" -w "%{http_code}" \
  "$BASE_URL/passkeys/list")"
if [[ "$STATUS_PASSKEY_LIST_UNAUTH" != "401" ]]; then
  echo "Expected /passkeys/list unauthenticated to return 401, got $STATUS_PASSKEY_LIST_UNAUTH"
  cat "$PASSKEY_LIST_UNAUTH_RESP"
  exit 1
fi
assert_contains "$PASSKEY_LIST_UNAUTH_RESP" '"ok":false'

echo "[router-security] Verifying JSON /passkeys/list succeeds for authenticated user"
STATUS_PASSKEY_LIST_AUTH="$(curl -sS -o "$PASSKEY_LIST_AUTH_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  "$BASE_URL/passkeys/list")"
if [[ "$STATUS_PASSKEY_LIST_AUTH" != "200" ]]; then
  echo "Expected /passkeys/list authenticated to return 200, got $STATUS_PASSKEY_LIST_AUTH"
  cat "$PASSKEY_LIST_AUTH_RESP"
  exit 1
fi
assert_contains "$PASSKEY_LIST_AUTH_RESP" '"ok":true'
assert_contains "$PASSKEY_LIST_AUTH_RESP" '"credentials":'

echo "[router-security] Verifying JSON /passkeys/revoke rejects missing CSRF"
STATUS_PASSKEY_REVOKE_NO_CSRF="$(curl -sS -o "$PASSKEY_REVOKE_NO_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/passkeys/revoke" \
  --data-urlencode "credential_id=test-credential")"
if [[ "$STATUS_PASSKEY_REVOKE_NO_CSRF" != "400" ]]; then
  echo "Expected /passkeys/revoke without CSRF to return 400, got $STATUS_PASSKEY_REVOKE_NO_CSRF"
  cat "$PASSKEY_REVOKE_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$PASSKEY_REVOKE_NO_CSRF_RESP" '"ok":false'

echo "[router-security] Verifying JSON /sessions rejects unauthenticated access"
STATUS_SESSIONS_LIST_UNAUTH="$(curl -sS -o "$SESSIONS_LIST_UNAUTH_RESP" -w "%{http_code}" \
  "$BASE_URL/sessions")"
if [[ "$STATUS_SESSIONS_LIST_UNAUTH" != "401" ]]; then
  echo "Expected /sessions unauthenticated to return 401, got $STATUS_SESSIONS_LIST_UNAUTH"
  cat "$SESSIONS_LIST_UNAUTH_RESP"
  exit 1
fi
assert_contains "$SESSIONS_LIST_UNAUTH_RESP" '"ok":false'

echo "[router-security] Verifying JSON /sessions succeeds for authenticated user"
STATUS_SESSIONS_LIST_AUTH="$(curl -sS -o "$SESSIONS_LIST_AUTH_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  "$BASE_URL/sessions")"
if [[ "$STATUS_SESSIONS_LIST_AUTH" != "200" ]]; then
  echo "Expected /sessions authenticated to return 200, got $STATUS_SESSIONS_LIST_AUTH"
  cat "$SESSIONS_LIST_AUTH_RESP"
  exit 1
fi
assert_contains "$SESSIONS_LIST_AUTH_RESP" '"ok":true'
assert_contains "$SESSIONS_LIST_AUTH_RESP" '"sessions":'

echo "[router-security] Verifying JSON /sessions/revoke rejects missing CSRF"
STATUS_SESSIONS_REVOKE_NO_CSRF="$(curl -sS -o "$SESSIONS_REVOKE_NO_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/sessions/revoke" \
  --data-urlencode "session_id=test-session")"
if [[ "$STATUS_SESSIONS_REVOKE_NO_CSRF" != "400" ]]; then
  echo "Expected /sessions/revoke without CSRF to return 400, got $STATUS_SESSIONS_REVOKE_NO_CSRF"
  cat "$SESSIONS_REVOKE_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$SESSIONS_REVOKE_NO_CSRF_RESP" '"ok":false'

CURRENT_SESSION_ID="$(sed -n 's/.*"session_id":"\([^"]*\)".*/\1/p' "$SESSIONS_LIST_AUTH_RESP" | head -n1)"
if [[ -z "$CURRENT_SESSION_ID" ]]; then
  echo "Expected /sessions response to include at least one session_id"
  cat "$SESSIONS_LIST_AUTH_RESP"
  exit 1
fi

echo "[router-security] Verifying JSON /sessions/revoke can revoke current session with CSRF"
STATUS_SESSIONS_REVOKE_WITH_CSRF="$(curl -sS -o "$SESSIONS_REVOKE_WITH_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -X POST "$BASE_URL/sessions/revoke" \
  --data-urlencode "session_id=${CURRENT_SESSION_ID}")"
if [[ "$STATUS_SESSIONS_REVOKE_WITH_CSRF" != "200" ]]; then
  echo "Expected /sessions/revoke with CSRF to return 200, got $STATUS_SESSIONS_REVOKE_WITH_CSRF"
  cat "$SESSIONS_REVOKE_WITH_CSRF_RESP"
  exit 1
fi
assert_contains "$SESSIONS_REVOKE_WITH_CSRF_RESP" '"ok":true'

echo "[router-security] Verifying current session revoke logs user out"
STATUS_PROFILE_AFTER_SESSION_REVOKE="$(curl -sS -o "$PROFILE_AFTER_SESSIONS_REVOKE_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  "$BASE_URL/profile")"
if [[ "$STATUS_PROFILE_AFTER_SESSION_REVOKE" != "401" ]]; then
  echo "Expected /profile after current session revoke to return 401, got $STATUS_PROFILE_AFTER_SESSION_REVOKE"
  cat "$PROFILE_AFTER_SESSIONS_REVOKE_RESP"
  exit 1
fi
assert_contains "$PROFILE_AFTER_SESSIONS_REVOKE_RESP" '"ok":false'

echo "[router-security] Re-authenticating after current session revoke"
curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL/ui/login" >"$LOGIN_PAGE"
CSRF_TOKEN="$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$LOGIN_PAGE" | head -n1)"
if [[ -z "$CSRF_TOKEN" ]]; then
  echo "Failed to parse CSRF token from login page after session revoke"
  cat "$LOGIN_PAGE"
  exit 1
fi
curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/ui/login" \
  --data-urlencode "csrf_token=${CSRF_TOKEN}" \
  --data-urlencode "identifier=${USERNAME}" \
  --data-urlencode "password=${PASSWORD}" >/dev/null

echo "[router-security] Verifying HTML /ui/passkeys requires auth"
STATUS_UI_PASSKEYS_UNAUTH="$(curl -sS -o "$UI_PASSKEYS_UNAUTH_RESP" -w "%{http_code}" "$BASE_URL/ui/passkeys")"
if [[ "$STATUS_UI_PASSKEYS_UNAUTH" != "401" ]]; then
  echo "Expected unauthenticated /ui/passkeys to return 401, got $STATUS_UI_PASSKEYS_UNAUTH"
  cat "$UI_PASSKEYS_UNAUTH_RESP"
  exit 1
fi

echo "[router-security] Verifying authenticated HTML /ui/passkeys is accessible"
STATUS_UI_PASSKEYS_AUTH="$(curl -sS -o "$UI_PASSKEYS_AUTH_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL/ui/passkeys")"
if [[ "$STATUS_UI_PASSKEYS_AUTH" != "200" ]]; then
  echo "Expected authenticated /ui/passkeys to return 200, got $STATUS_UI_PASSKEYS_AUTH"
  cat "$UI_PASSKEYS_AUTH_RESP"
  exit 1
fi
assert_contains "$UI_PASSKEYS_AUTH_RESP" 'Passkeys'

echo "[router-security] Verifying HTML /ui/passkeys/revoke rejects missing CSRF"
STATUS_UI_PASSKEYS_REVOKE_NO_CSRF="$(curl -sS -o "$UI_PASSKEYS_REVOKE_NO_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/ui/passkeys/revoke" \
  --data-urlencode "credential_id=test-credential")"
if [[ "$STATUS_UI_PASSKEYS_REVOKE_NO_CSRF" != "400" ]]; then
  echo "Expected /ui/passkeys/revoke without CSRF to return 400, got $STATUS_UI_PASSKEYS_REVOKE_NO_CSRF"
  cat "$UI_PASSKEYS_REVOKE_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$UI_PASSKEYS_REVOKE_NO_CSRF_RESP" 'Invalid request'

echo "[router-security] Verifying HTML /ui/sessions requires auth"
STATUS_UI_SESSIONS_UNAUTH="$(curl -sS -o "$UI_SESSIONS_UNAUTH_RESP" -w "%{http_code}" "$BASE_URL/ui/sessions")"
if [[ "$STATUS_UI_SESSIONS_UNAUTH" != "401" ]]; then
  echo "Expected unauthenticated /ui/sessions to return 401, got $STATUS_UI_SESSIONS_UNAUTH"
  cat "$UI_SESSIONS_UNAUTH_RESP"
  exit 1
fi

echo "[router-security] Verifying authenticated HTML /ui/sessions is accessible"
STATUS_UI_SESSIONS_AUTH="$(curl -sS -o "$UI_SESSIONS_AUTH_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL/ui/sessions")"
if [[ "$STATUS_UI_SESSIONS_AUTH" != "200" ]]; then
  echo "Expected authenticated /ui/sessions to return 200, got $STATUS_UI_SESSIONS_AUTH"
  cat "$UI_SESSIONS_AUTH_RESP"
  exit 1
fi
assert_contains "$UI_SESSIONS_AUTH_RESP" 'Sessions &amp; Devices'

echo "[router-security] Verifying HTML /ui/sessions/revoke rejects missing CSRF"
STATUS_UI_SESSIONS_REVOKE_NO_CSRF="$(curl -sS -o "$UI_SESSIONS_REVOKE_NO_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/ui/sessions/revoke" \
  --data-urlencode "session_id=test-session")"
if [[ "$STATUS_UI_SESSIONS_REVOKE_NO_CSRF" != "400" ]]; then
  echo "Expected /ui/sessions/revoke without CSRF to return 400, got $STATUS_UI_SESSIONS_REVOKE_NO_CSRF"
  cat "$UI_SESSIONS_REVOKE_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$UI_SESSIONS_REVOKE_NO_CSRF_RESP" 'Invalid request'

echo "[router-security] Verifying HTML /ui/totp/enroll requires auth"
STATUS_TOTP_UI_UNAUTH="$(curl -sS -o "$UI_TOTP_PAGE_RESP" -w "%{http_code}" "$BASE_URL/ui/totp/enroll")"
if [[ "$STATUS_TOTP_UI_UNAUTH" != "401" ]]; then
  echo "Expected unauthenticated /ui/totp/enroll to return 401, got $STATUS_TOTP_UI_UNAUTH"
  cat "$UI_TOTP_PAGE_RESP"
  exit 1
fi

echo "[router-security] Verifying authenticated HTML /ui/totp/enroll is accessible"
STATUS_TOTP_UI_AUTH="$(curl -sS -o "$UI_TOTP_PAGE_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL/ui/totp/enroll")"
if [[ "$STATUS_TOTP_UI_AUTH" != "200" ]]; then
  echo "Expected authenticated /ui/totp/enroll to return 200, got $STATUS_TOTP_UI_AUTH"
  cat "$UI_TOTP_PAGE_RESP"
  exit 1
fi
assert_contains "$UI_TOTP_PAGE_RESP" 'TOTP Enrollment'

echo "[router-security] Verifying HTML /ui/totp/enroll/begin rejects missing CSRF"
STATUS_TOTP_NO_CSRF="$(curl -sS -o "$UI_TOTP_NO_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$BASE_URL/ui/totp/enroll/begin")"
if [[ "$STATUS_TOTP_NO_CSRF" != "400" ]]; then
  echo "Expected /ui/totp/enroll/begin without CSRF to return 400, got $STATUS_TOTP_NO_CSRF"
  cat "$UI_TOTP_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$UI_TOTP_NO_CSRF_RESP" 'Invalid request'

echo "[router-security] Verifying HTML /ui/recovery-codes/regenerate rejects missing CSRF"
STATUS_UI_RECOVERY_NO_CSRF="$(curl -sS -o "$UI_RECOVERY_NO_CSRF_RESP" -w "%{http_code}" -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$BASE_URL/ui/recovery-codes/regenerate")"
if [[ "$STATUS_UI_RECOVERY_NO_CSRF" != "400" ]]; then
  echo "Expected /ui/recovery-codes/regenerate without CSRF to return 400, got $STATUS_UI_RECOVERY_NO_CSRF"
  cat "$UI_RECOVERY_NO_CSRF_RESP"
  exit 1
fi
assert_contains "$UI_RECOVERY_NO_CSRF_RESP" 'Invalid request'

echo "[router-security] Verifying HTML /ui/step-up/verify GET is accessible"
STATUS_STEPUP_UI="$(curl -sS -o "$UI_STEPUP_RESP" -w "%{http_code}" "$BASE_URL/ui/step-up/verify")"
if [[ "$STATUS_STEPUP_UI" != "200" ]]; then
  echo "Expected /ui/step-up/verify to return 200, got $STATUS_STEPUP_UI"
  cat "$UI_STEPUP_RESP"
  exit 1
fi
assert_contains "$UI_STEPUP_RESP" 'Step-up Verification'

echo "[router-security] Verifying /step-up/verify accepts recovery-code input and returns generic failure without challenge"
STATUS_STEPUP_RECOVERY="$(curl -sS -o "$STEPUP_RECOVERY_RESP" -w "%{http_code}" \
  -X POST "$BASE_URL/step-up/verify" \
  --data-urlencode "recovery_code=ABCD-EFGH")"
if [[ "$STATUS_STEPUP_RECOVERY" != "200" ]]; then
  echo "Expected /step-up/verify to return 200, got $STATUS_STEPUP_RECOVERY"
  cat "$STEPUP_RECOVERY_RESP"
  exit 1
fi
assert_contains "$STEPUP_RECOVERY_RESP" '"ok":false'
assert_contains "$STEPUP_RECOVERY_RESP" 'Invalid verification code.'

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
