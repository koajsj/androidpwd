package com.offlinevault.security

import java.security.SecureRandom
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec

/**
 * AES key whose backing bytes can be actively cleared.
 *
 * Android's regular [SecretKeySpec] does not expose a reliable cross-version destruction API.
 * Keeping app-managed DEKs/KEKs in this small implementation lets lock/cancellation paths erase
 * their backing array instead of waiting for a future garbage collection.
 */
private class ClearableAesKey(keyBytes: ByteArray) : SecretKey {
    private val material = keyBytes.copyOf()

    @Volatile
    private var cleared = false

    override fun getAlgorithm(): String = "AES"
    override fun getFormat(): String = "RAW"

    @Synchronized
    override fun getEncoded(): ByteArray {
        check(!cleared) { "Key material has been cleared" }
        return material.copyOf()
    }

    @Synchronized
    fun clear() {
        if (!cleared) {
            material.fill(0)
            cleared = true
        }
    }
}

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
     * devices. This cost does not make a short PIN or a guessable recovery answer resistant to
     * offline guessing by an attacker who obtains the wrapped key. The count
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
            keyFromBytes(keyBytes)
        } finally {
            keyBytes.fill(0)
        }
    }

    /** Copies raw AES-256 material into an app-managed key that can later be actively cleared. */
    fun keyFromBytes(bytes: ByteArray): SecretKey {
        require(bytes.size == AES_KEY_BITS / 8) { "Invalid AES-256 key length" }
        return ClearableAesKey(bytes)
    }

    /** Best-effort active destruction for keys created by this manager. */
    fun destroyKey(key: SecretKey?) {
        (key as? ClearableAesKey)?.clear()
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
                return keyFromBytes(keyBytes)
            } finally {
                keyBytes.fill(0)
            }
        } finally {
            pbeSpec.clearPassword()
            password.fill('\u0000')
        }
    }

    /**
     * Encrypts [plaintext] with AES-256-GCM. Returns IV || ciphertext+tag.
     *
     * [aad] binds the ciphertext to its record/field context and prevents a valid ciphertext from
     * being transplanted into a different field. Legacy callers may omit it for old wire formats.
     */
    fun encrypt(key: SecretKey, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = randomBytes(IV_LENGTH)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        return try {
            iv + ciphertext
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    /** Decrypts a IV || ciphertext+tag blob produced by [encrypt]. Throws on tampering / wrong key. */
    fun decrypt(key: SecretKey, blob: ByteArray, aad: ByteArray? = null): ByteArray {
        // A valid blob is at least IV (12) + the GCM authentication tag (16 bytes).
        require(blob.size >= IV_LENGTH + GCM_TAG_BITS / 8) { "Ciphertext too short" }
        val iv = blob.copyOfRange(0, IV_LENGTH)
        val ciphertext = blob.copyOfRange(IV_LENGTH, blob.size)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            if (aad != null) cipher.updateAAD(aad)
            cipher.doFinal(ciphertext)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    fun encryptString(key: SecretKey, plaintext: String, aad: String? = null): String {
        val bytes = plaintext.toByteArray(Charsets.UTF_8)
        val aadBytes = aad?.toByteArray(Charsets.UTF_8)
        return try {
            val encrypted = encrypt(key, bytes, aadBytes)
            try {
                encode(encrypted)
            } finally {
                encrypted.fill(0)
            }
        } finally {
            bytes.fill(0)
            aadBytes?.fill(0)
        }
    }

    fun decryptString(key: SecretKey, encoded: String, aad: String? = null): String {
        val blob = decode(encoded)
        val aadBytes = aad?.toByteArray(Charsets.UTF_8)
        val bytes = try {
            decrypt(key, blob, aadBytes)
        } finally {
            blob.fill(0)
            aadBytes?.fill(0)
        }
        return try {
            String(bytes, Charsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }

    fun encode(bytes: ByteArray): String = Base64.getEncoder().withoutPadding().encodeToString(bytes)

    fun decode(value: String): ByteArray = Base64.getDecoder().decode(value)

    fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return try {
            digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        } finally {
            digest.fill(0)
        }
    }
}
