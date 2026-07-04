<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use HealthVault\CryptoVault;
use HealthVault\Authenticator;

final class CryptoVaultTest extends TestCase
{
    private CryptoVault $vault;

    protected function setUp(): void
    {
        // 256-bit test key (64 hex chars). In production this comes from .env.
        $this->vault = new CryptoVault(str_repeat('a1', 32));
    }

    /** STATE 1: untampered lifecycle — decrypt(encrypt(x)) === x. */
    public function testUntamperedRoundTripReturnsOriginalPlaintext(): void
    {
        $plaintext = 'DIAGNOSIS: Stage-2 Carcinoma. STATUS: Critical.';
        $envelope  = $this->vault->encrypt($plaintext);

        $this->assertNotSame($plaintext, $envelope, 'Envelope must be ciphertext, not plaintext.');
        $this->assertSame($plaintext, $this->vault->decrypt($envelope));
    }

    /** Confidentiality: identical plaintexts must NOT produce identical envelopes (no ECB leakage). */
    public function testIdenticalPlaintextsProduceDifferentEnvelopes(): void
    {
        $p = 'DIAGNOSIS: Acute Type-2 Diabetes.';
        $this->assertNotSame(
            $this->vault->encrypt($p),
            $this->vault->encrypt($p),
            'Random per-message IV must make ciphertexts diverge.'
        );
    }

    /** STATE 2: tampered ciphertext must raise an AEAD authentication exception. */
    public function testTamperedCiphertextThrowsAeadException(): void
    {
        $envelope = $this->vault->encrypt('Controlled substance: opioid 5mg');

        // Flip one byte in the middle of the raw envelope to simulate tampering.
        $raw = base64_decode($envelope, true);
        $mid = intdiv(strlen($raw), 2);
        $raw[$mid] = ($raw[$mid] === "\x00") ? "\x01" : "\x00";
        $tampered = base64_encode($raw);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Authentication failed');
        $this->vault->decrypt($tampered);
    }

    /** A truncated / malformed envelope also fails closed. */
    public function testMalformedEnvelopeFailsClosed(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->vault->decrypt('not-a-valid-envelope');
    }

    /** STATE 3: credential hash integrity — Argon2id verify matches only the correct key. */
    public function testArgon2idCredentialHashIntegrity(): void
    {
        $hash = Authenticator::hashKey('doctorsecret');

        $this->assertStringStartsWith('$argon2id$', $hash, 'Must use Argon2id, not MD5.');
        $this->assertTrue(Authenticator::verify('doctorsecret', $hash));
        $this->assertFalse(Authenticator::verify('wrongsecret', $hash));
    }

    /** Boundary: multi-byte characters are counted by character, not by byte. */
    public function testMultibyteBoundaryUsesCharacterLength(): void
    {
        // 256 three-byte characters = 768 bytes. Byte logic would reject at >256
        // bytes; character logic must accept exactly 256 characters.
        $exactly256Chars = str_repeat("あ", 256);
        $this->assertTrue(Authenticator::withinBoundary($exactly256Chars));

        $tooLong = str_repeat("あ", 257);
        $this->assertFalse(Authenticator::withinBoundary($tooLong));
    }
}
