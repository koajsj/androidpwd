package com.offlinevault.security

/**
 * Persisted description of the password-based key derivation algorithm.
 *
 * Keeping the algorithm identifier separate from its cost avoids tying stored vault material to
 * a single implementation forever. Existing material without a version is PBKDF2 v1; a future
 * Argon2id implementation can add its own identifier without guessing how old material was made.
 */
data class KdfSpec(
    val version: String,
    val iterations: Int
)

object KdfVersions {
    const val PBKDF2_HMAC_SHA256_V1 = "pbkdf2-hmac-sha256-v1"

    /** Reserved on-disk identifier. It is deliberately rejected until an audited implementation ships. */
    const val ARGON2ID_V1 = "argon2id-v1"

    fun current(iterations: Int = CryptoManager.DEFAULT_PBKDF2_ITERATIONS): KdfSpec =
        KdfSpec(PBKDF2_HMAC_SHA256_V1, iterations)

    /** Missing versions belong to the pre-versioned PBKDF2 format. */
    fun stored(version: String?, iterations: Int): KdfSpec {
        val normalized = version?.trim().orEmpty().ifBlank { PBKDF2_HMAC_SHA256_V1 }
        require(normalized == PBKDF2_HMAC_SHA256_V1) { "Unsupported KDF version" }
        return KdfSpec(normalized, CryptoManager.requireValidIterations(iterations))
    }
}
