#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[security-tests] Running request context sanitization test"
php "$ROOT_DIR/tests/security/request_context_test.php"

echo "[security-tests] Running PHP mail header-hardening test"
php "$ROOT_DIR/tests/security/php_mail_mailer_test.php"

echo "[security-tests] Running profile field policy hardening test"
php "$ROOT_DIR/tests/security/profile_field_policy_test.php"

echo "[security-tests] Running router security integration tests"
bash "$ROOT_DIR/tests/security/router_security_test.sh"

echo "[security-tests] All security tests passed"
