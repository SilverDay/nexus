<?php
declare(strict_types=1);

namespace Nexus\DropInUser\Service;

use Nexus\DropInUser\Contract\AuditLoggerInterface;
use Nexus\DropInUser\Contract\TotpServiceInterface;
use Nexus\DropInUser\Observability\RequestContext;
use PDO;

final class TotpService implements TotpServiceInterface
{
	public function __construct(
		private readonly PDO $pdo,
		private readonly AuditLoggerInterface $auditLogger,
		private readonly RequestContext $requestContext,
		private readonly string $encryptionKey,
		private readonly string $issuer = 'Nexus User Module',
	) {
	}

	public function beginEnrollment(int $userId): string
	{
		if ($userId <= 0) {
			throw new \RuntimeException('Invalid user id.');
		}

		$secret = $this->base32Encode(random_bytes(20));
		$secretEncrypted = $this->encryptSecret($secret);

		$stmt = $this->pdo->prepare(
			'INSERT INTO user_totp_factors (user_id, secret_enc, pending_expires_at, confirmed_at)
			 VALUES (:user_id, :secret_enc, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 10 MINUTE), NULL)
			 ON DUPLICATE KEY UPDATE
			   secret_enc = VALUES(secret_enc),
			   pending_expires_at = VALUES(pending_expires_at),
			   confirmed_at = NULL,
			   updated_at = CURRENT_TIMESTAMP'
		);
		$stmt->execute([
			'user_id' => $userId,
			'secret_enc' => $secretEncrypted,
		]);

		$user = $this->fetchUserIdentity($userId);
		$accountLabel = rawurlencode(($user['email'] ?? '') !== '' ? (string) $user['email'] : (string) ($user['username'] ?? ('user-' . $userId)));
		$issuer = rawurlencode($this->issuer);

		$context = $this->requestContext->asAuditContext();
		$this->auditLogger->log('auth.totp.enrollment_started', $userId, $userId, $context);

		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
			$issuer,
			$accountLabel,
			$secret,
			$issuer
		);
	}

	public function confirmEnrollment(int $userId, string $otpCode): bool
	{
		$row = $this->fetchTotpRow($userId);
		if ($row === null || !isset($row['pending_expires_at']) || $row['pending_expires_at'] === null) {
			return false;
		}

		if (strtotime((string) $row['pending_expires_at']) <= time()) {
			return false;
		}

		$secret = $this->decryptSecret((string) $row['secret_enc']);
		if (!$this->isCodeValid($secret, $otpCode)) {
			return false;
		}

		$update = $this->pdo->prepare(
			'UPDATE user_totp_factors
			 SET confirmed_at = UTC_TIMESTAMP(), pending_expires_at = NULL, last_used_at = UTC_TIMESTAMP()
			 WHERE user_id = :user_id'
		);
		$update->execute(['user_id' => $userId]);

		$context = $this->requestContext->asAuditContext();
		$this->auditLogger->log('auth.totp.enrollment_confirmed', $userId, $userId, $context);

		return true;
	}

	public function verifyCode(int $userId, string $otpCode): bool
	{
		$row = $this->fetchTotpRow($userId);
		if ($row === null || !isset($row['confirmed_at']) || $row['confirmed_at'] === null) {
			return false;
		}

		$secret = $this->decryptSecret((string) $row['secret_enc']);
		if (!$this->isCodeValid($secret, $otpCode)) {
			return false;
		}

		$update = $this->pdo->prepare('UPDATE user_totp_factors SET last_used_at = UTC_TIMESTAMP() WHERE user_id = :user_id');
		$update->execute(['user_id' => $userId]);

		return true;
	}

	/**
	 * @return array<string, mixed>|null
	 */
	private function fetchTotpRow(int $userId): ?array
	{
		$stmt = $this->pdo->prepare(
			'SELECT user_id, secret_enc, pending_expires_at, confirmed_at
			 FROM user_totp_factors
			 WHERE user_id = :user_id
			 LIMIT 1'
		);
		$stmt->execute(['user_id' => $userId]);
		$row = $stmt->fetch(PDO::FETCH_ASSOC);

		return is_array($row) ? $row : null;
	}

	/**
	 * @return array<string, mixed>
	 */
	private function fetchUserIdentity(int $userId): array
	{
		$stmt = $this->pdo->prepare('SELECT username, email FROM users WHERE id = :id LIMIT 1');
		$stmt->execute(['id' => $userId]);
		$row = $stmt->fetch(PDO::FETCH_ASSOC);

		return is_array($row) ? $row : [];
	}

	private function isCodeValid(string $secretBase32, string $otpCode): bool
	{
		$normalizedCode = preg_replace('/\D+/', '', $otpCode);
		if (!is_string($normalizedCode) || strlen($normalizedCode) !== 6) {
			return false;
		}

		$secret = $this->base32Decode($secretBase32);
		if ($secret === '') {
			return false;
		}

		$timeStep = (int) floor(time() / 30);
		for ($offset = -1; $offset <= 1; $offset++) {
			$expected = $this->generateTotp($secret, $timeStep + $offset);
			if (hash_equals($expected, $normalizedCode)) {
				return true;
			}
		}

		return false;
	}

	private function generateTotp(string $secret, int $counter): string
	{
		$counterBytes = pack('N2', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
		$hash = hash_hmac('sha1', $counterBytes, $secret, true);

		$offset = ord($hash[19]) & 0x0F;
		$binary = ((ord($hash[$offset]) & 0x7F) << 24)
			| ((ord($hash[$offset + 1]) & 0xFF) << 16)
			| ((ord($hash[$offset + 2]) & 0xFF) << 8)
			| (ord($hash[$offset + 3]) & 0xFF);

		return str_pad((string) ($binary % 1000000), 6, '0', STR_PAD_LEFT);
	}

	private function encryptSecret(string $secret): string
	{
		if ($this->encryptionKey === '') {
			throw new \RuntimeException('TOTP encryption key is missing.');
		}

		$key = hash('sha256', $this->encryptionKey, true);
		$iv = random_bytes(12);
		$tag = '';
		$ciphertext = openssl_encrypt($secret, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
		if ($ciphertext === false) {
			throw new \RuntimeException('Unable to encrypt TOTP secret.');
		}

		return base64_encode($iv . $tag . $ciphertext);
	}

	private function decryptSecret(string $encrypted): string
	{
		if ($this->encryptionKey === '') {
			throw new \RuntimeException('TOTP encryption key is missing.');
		}

		$decoded = base64_decode($encrypted, true);
		if (!is_string($decoded) || strlen($decoded) < 28) {
			throw new \RuntimeException('Invalid encrypted TOTP secret.');
		}

		$iv = substr($decoded, 0, 12);
		$tag = substr($decoded, 12, 16);
		$ciphertext = substr($decoded, 28);
		$key = hash('sha256', $this->encryptionKey, true);

		$plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
		if ($plaintext === false) {
			throw new \RuntimeException('Unable to decrypt TOTP secret.');
		}

		return $plaintext;
	}

	private function base32Encode(string $binary): string
	{
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits = '';
		foreach (str_split($binary) as $char) {
			$bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
		}

		$encoded = '';
		foreach (str_split($bits, 5) as $chunk) {
			$chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
			$encoded .= $alphabet[bindec($chunk)];
		}

		return $encoded;
	}

	private function base32Decode(string $base32): string
	{
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$normalized = strtoupper(preg_replace('/[^A-Z2-7]/', '', $base32) ?? '');
		if ($normalized === '') {
			return '';
		}

		$bits = '';
		foreach (str_split($normalized) as $char) {
			$position = strpos($alphabet, $char);
			if ($position === false) {
				return '';
			}

			$bits .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
		}

		$decoded = '';
		foreach (str_split($bits, 8) as $chunk) {
			if (strlen($chunk) < 8) {
				continue;
			}

			$decoded .= chr(bindec($chunk));
		}

		return $decoded;
	}
}