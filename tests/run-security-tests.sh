#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[security-tests] Running request context sanitization test"
php "$ROOT_DIR/tests/security/request_context_test.php"

echo "[security-tests] Running PHP mail header-hardening test"
php "$ROOT_DIR/tests/security/php_mail_mailer_test.php"

echo "[security-tests] Running profile field policy hardening test"
php "$ROOT_DIR/tests/security/profile_field_policy_test.php"

echo "[security-tests] Running module config loader test"
php "$ROOT_DIR/tests/security/module_config_loader_test.php"

echo "[security-tests] Running configurable email template provider test"
php "$ROOT_DIR/tests/security/configurable_email_template_provider_test.php"

echo "[security-tests] Running file email template provider test"
php "$ROOT_DIR/tests/security/file_email_template_provider_test.php"

echo "[security-tests] Running admin registration notification test"
php "$ROOT_DIR/tests/security/auth_service_admin_registration_notification_test.php"

echo "[security-tests] Running verify link template test"
php "$ROOT_DIR/tests/security/auth_service_verify_link_template_test.php"

echo "[security-tests] Running mailer factory test"
php "$ROOT_DIR/tests/security/mailer_factory_test.php"

echo "[security-tests] Running null passkey service test"
php "$ROOT_DIR/tests/security/passkey_null_service_test.php"

echo "[security-tests] Running null passkey ceremony validator test"
php "$ROOT_DIR/tests/security/null_passkey_ceremony_validator_test.php"

echo "[security-tests] Running DatabasePasskeyService payload-shape test"
php "$ROOT_DIR/tests/security/database_passkey_service_payload_test.php"

echo "[security-tests] Running router security integration tests"
bash "$ROOT_DIR/tests/security/router_security_test.sh"

echo "[security-tests] All security tests passed"
