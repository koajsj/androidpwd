package com.offlinevault.security

import java.security.SecureRandom
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Low level cryptographic primitives used across the app.
 *
 * - AES-256-GCM for authenticated symmetric encryption.
 * - PBKDF2WithHmacSHA256 for key derivation from the master password / recovery answer.
 * - SecureRandom for salt, IV and the Data Encryption Key (DEK).
 *
 * The "secret box" wire format produced by [encrypt] is:  IV (12 bytes) || ciphertext+GCM tag.
 * It is stored Base64 encoded so it is safe to keep inside Room TEXT columns or DataStore.
 */
object CryptoManager {

    private const val AES_KEY_BITS = 256
    private const val GCM_TAG_BITS = 128
    private const val IV_LENGTH = 12
    const val SALT_LENGTH = 16

    /**
     * PBKDF2 iteration count for newly created material. 300k keeps unlock responsive on older
     * devices while staying comfortably above the OWASP minimum for PBKDF2-HMAC-SHA256. The count
     * is stored per vault, so it can be raised later without locking existing vaults out. Always run
     * on a background dispatcher so the one-off cost stays off the main thread.
     */
    const val DEFAULT_PBKDF2_ITERATIONS = 300_000

    /**
     * Iteration count used by vaults / backups created before the count was persisted. Material that
     * carries no stored iteration count is assumed to use this value so it can still be unlocked.
     */
    const val LEGACY_PBKDF2_ITERATIONS = 120_000

    /** Reject corrupted or attacker-controlled KDF costs before starting expensive work. */
    const val MIN_PBKDF2_ITERATIONS = 100_000
    const val MAX_PBKDF2_ITERATIONS = 2_000_000

    fun requireValidIterations(iterations: Int): Int = iterations.also {
        require(it in MIN_PBKDF2_ITERATIONS..MAX_PBKDF2_ITERATIONS) {
            "Invalid PBKDF2 iteration count"
        }
    }

    private val secureRandom = SecureRandom()

    fun randomBytes(length: Int): ByteArray = ByteArray(length).also { secureRandom.nextBytes(it) }

    fun newSalt(): ByteArray = randomBytes(SALT_LENGTH)

    /** Generates a fresh random 256-bit Data Encryption Key. */
    fun newDataEncryptionKey(): SecretKey {
        val keyBytes = randomBytes(AES_KEY_BITS / 8)
        return try {
            SecretKeySpec(keyBytes, "AES")
        } finally {
            keyBytes.fill(0)
        }
    }

    /**
     * Derives a 256-bit AES key from a password and salt using PBKDF2WithHmacSHA256.
     * The supplied [password] char array is cleared after use.
     */
    fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = DEFAULT_PBKDF2_ITERATIONS
    ): SecretKey = deriveKey(password, salt, KdfVersions.current(iterations))

    /** Derives a key according to an explicitly persisted [KdfSpec]. */
    fun deriveKey(password: CharArray, salt: ByteArray, spec: KdfSpec): SecretKey {
        require(salt.size == SALT_LENGTH) { "Invalid salt length" }
        require(spec.version == KdfVersions.PBKDF2_HMAC_SHA256_V1) { "Unsupported KDF version" }
        val pbeSpec = PBEKeySpec(password, salt, requireValidIterations(spec.iterations), AES_KEY_BITS)
        try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val keyBytes = factory.generateSecret(pbeSpec).encoded
            try {
                return SecretKeySpec(keyBytes, "AES")
            } finally {
                keyBytes.fill(0)
            }
        } finally {
            pbeSpec.clearPassword()
            password.fill('\u0000')
        }
    }

    /** Encrypts [plaintext] with AES-256-GCM. Returns IV || ciphertext+tag. */
    fun encrypt(key: SecretKey, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = randomBytes(IV_LENGTH)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val ciphertext = cipher.doFinal(plaintext)
        return iv + ciphertext
    }

    /** Decrypts a IV || ciphertext+tag blob produced by [encrypt]. Throws on tampering / wrong key. */
    fun decrypt(key: SecretKey, blob: ByteArray): ByteArray {
        // A valid blob is at least IV (12) + the GCM authentication tag (16 bytes).
        require(blob.size >= IV_LENGTH + GCM_TAG_BITS / 8) { "Ciphertext too short" }
        val iv = blob.copyOfRange(0, IV_LENGTH)
        val ciphertext = blob.copyOfRange(IV_LENGTH, blob.size)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.doFinal(ciphertext)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    fun encryptString(key: SecretKey, plaintext: String): String {
        val bytes = plaintext.toByteArray(Charsets.UTF_8)
        return try {
            encode(encrypt(key, bytes))
        } finally {
            bytes.fill(0)
        }
    }

    fun decryptString(key: SecretKey, encoded: String): String {
        val bytes = decrypt(key, decode(encoded))
        return try {
            String(bytes, Charsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }

    fun encode(bytes: ByteArray): String = Base64.getEncoder().withoutPadding().encodeToString(bytes)

    fun decode(value: String): ByteArray = Base64.getDecoder().decode(value)

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
