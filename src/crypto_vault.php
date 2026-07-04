<?php
declare(strict_types=1);

namespace HealthVault;

use RuntimeException;

final class CryptoVault
{
    private const CIPHER   = 'aes-256-gcm';
    private const IV_LEN   = 12;   // 96-bit nonce recommended by NIST SP 800-38D
    private const TAG_LEN  = 16;   // 128-bit authentication tag
    private const KEY_LEN  = 32;   // 256-bit key

    /** @var string raw 32-byte key */
    private string $key;

    /**
     * @param string $keyMaterial Raw or hex/base64 key sourced from the environment.
     */
    public function __construct(string $keyMaterial)
    {
        // Accept a hex-encoded 64-char key or a raw 32-byte key.
        if (ctype_xdigit($keyMaterial) && strlen($keyMaterial) === 64) {
            $keyMaterial = hex2bin($keyMaterial);
        }

        if (strlen($keyMaterial) !== self::KEY_LEN) {
            throw new RuntimeException(
                'Invalid key length: AES-256-GCM requires a 32-byte key.'
            );
        }
        $this->key = $keyMaterial;
    }

    /**
     * Encrypt a plaintext payload.
     * Returns a transport-safe base64 envelope: IV || CIPHERTEXT || TAG.
     */
    public function encrypt(string $plaintext): string
    {
        // Fresh, unpredictable nonce for every single message.
        $iv  = random_bytes(self::IV_LEN);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,   // raw bytes, not base64
            $iv,
            $tag,               // populated by reference with the GMAC tag
            '',                 // associated data (none here)
            self::TAG_LEN
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Encryption failed.');
        }

        // Serialize: IV first, ciphertext middle, tag last -> then base64.
        return base64_encode($iv . $ciphertext . $tag);
    }

    /**
     * Decrypt a base64 envelope produced by encrypt().
     * Throws on any tampering or malformed input (fail-closed).
     */
    public function decrypt(string $envelope): string
    {
        $raw = base64_decode($envelope, true);
        if ($raw === false) {
            throw new RuntimeException('Malformed envelope: invalid base64.');
        }

        // Minimum viable length = IV + at least 0 ciphertext + TAG.
        if (strlen($raw) < self::IV_LEN + self::TAG_LEN) {
            throw new RuntimeException('Malformed envelope: truncated payload.');
        }

        // Deterministic byte slicing back into the three components.
        $iv         = substr($raw, 0, self::IV_LEN);
        $tag        = substr($raw, -self::TAG_LEN);
        $ciphertext = substr($raw, self::IV_LEN, -self::TAG_LEN);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        // openssl_decrypt returns false when the GMAC tag does not verify.
        if ($plaintext === false) {
            throw new RuntimeException(
                'Authentication failed: ciphertext has been tampered with.'
            );
        }

        return $plaintext;
    }
}

/**
 * ---------------------------------------------------------------------------
 * HTTP front controller (only runs when this file is requested directly).
 * Kept thin; all crypto logic lives in the testable CryptoVault class above.
 * ---------------------------------------------------------------------------
 */
if (PHP_SAPI !== 'cli' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    require_once __DIR__ . '/env.php';   // loads getenv('VAULT_KEY') from .env

    header('Content-Type: application/json');

    try {
        $keyHex = getenv('VAULT_KEY');
        if ($keyHex === false || $keyHex === '') {
            throw new RuntimeException('VAULT_KEY is not configured.');
        }

        $vault   = new CryptoVault($keyHex);
        $payload = (string)($_POST['payload'] ?? '');
        $envelope = $vault->encrypt($payload);

        echo json_encode(['status' => 'vaulted', 'data' => $envelope]);
    } catch (\Throwable $e) {
        // Isolated failure state: no key material or internals leaked.
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Vault operation failed.']);
    }
}
