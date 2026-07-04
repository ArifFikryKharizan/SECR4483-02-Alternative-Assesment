<?php
declare(strict_types=1);

namespace HealthVault;

final class Authenticator
{
    private const MAX_KEY_CHARS = 256;

    /** Argon2id cost parameters (tune to hardware; these are sane baselines). */
    private const ARGON_OPTS = [
        'memory_cost' => 65536,  // 64 MiB of RAM per hash  (memory-hardness)
        'time_cost'   => 4,      // 4 iterations            (time-hardness)
        'threads'     => 2,      // parallelism lanes
    ];

    /**
     * Produce an Argon2id hash for storage. Salt is generated internally and
     * embedded in the returned string; never store or reuse a manual salt.
     */
    public static function hashKey(string $plainKey): string
    {
        return password_hash($plainKey, PASSWORD_ARGON2ID, self::ARGON_OPTS);
    }

    /**
     * Validate the input boundary using SEMANTIC character length.
     * Returns false if the charset is invalid or the length exceeds the bound.
     */
    public static function withinBoundary(string $inputKey): bool
    {
        // Reject anything that is not well-formed UTF-8 outright.
        if (!mb_check_encoding($inputKey, 'UTF-8')) {
            return false;
        }
        // mb_strlen counts characters (code points), NOT bytes.
        return mb_strlen($inputKey, 'UTF-8') <= self::MAX_KEY_CHARS;
    }

    /**
     * Verify a candidate key against a stored Argon2id hash in constant time.
     */
    public static function verify(string $inputKey, string $storedHash): bool
    {
        return password_verify($inputKey, $storedHash);
    }

    /**
     * Report whether a stored hash should be upgraded to current parameters
     * (e.g. a legacy MD5 hash, or Argon2id with weaker costs).
     */
    public static function needsRehash(string $storedHash): bool
    {
        return password_needs_rehash($storedHash, PASSWORD_ARGON2ID, self::ARGON_OPTS);
    }
}

/**
 * ---------------------------------------------------------------------------
 * HTTP front controller (only runs on a direct POST request).
 * ---------------------------------------------------------------------------
 */
if (PHP_SAPI !== 'cli' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    require_once __DIR__ . '/db_config.php';   // provides $pdo (PDO instance)

    $inputKey = (string)($_POST['auth_key'] ?? '');

    // Boundary is now measured in characters, not bytes.
    if (!Authenticator::withinBoundary($inputKey)) {
        http_response_code(400);
        exit('Rejected: invalid or oversized authentication key.');
    }

    // Fetch the stored Argon2id hash for the requesting user (parameterized).
    $username = (string)($_POST['username'] ?? '');
    $stmt = $pdo->prepare(
        'SELECT auth_key_hash FROM staff_credentials WHERE username = :u LIMIT 1'
    );
    $stmt->execute([':u' => $username]);
    $row = $stmt->fetch();

    if ($row && Authenticator::verify($inputKey, $row['auth_key_hash'])) {
        echo 'Access Granted.';

        // Transparent upgrade: if the stored hash used weaker parameters,
        // re-hash on successful login (migration path off legacy MD5).
        if (Authenticator::needsRehash($row['auth_key_hash'])) {
            $new = Authenticator::hashKey($inputKey);
            $upd = $pdo->prepare(
                'UPDATE staff_credentials SET auth_key_hash = :h WHERE username = :u'
            );
            $upd->execute([':h' => $new, ':u' => $username]);
        }
    } else {
        http_response_code(401);
        echo 'Access Denied.';   // uniform message: no user enumeration
    }
}
