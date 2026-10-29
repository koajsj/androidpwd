package com.offlinevault.security

/**
 * Versioned field encryption for database values.
 *
 * v1 authenticated only the ciphertext. v2 additionally binds it to a stable record/field context
 * through AES-GCM AAD, preventing valid ciphertext from being moved between fields or records.
 */
object EncryptedField {
    /** Length-prefix IDs so imported identifiers cannot create an ambiguous AAD context. */
    fun customFieldsContext(credentialId: String, vaultId: String): String =
        "credential-custom:${vaultId.length}:$vaultId:${credentialId.length}:$credentialId"
    private const val PREFIX_V1 = "enc:v1:"
    private const val PREFIX_V2 = "enc:v2:"
    // Password-history rows used to reuse the live credential envelope. v3 gives every history
    // row its own authenticated context while retaining a distinguishable legacy fallback.
    private const val PREFIX_V3_HISTORY = "enc:v3:"
    private const val AAD_DOMAIN = "offline-vault-field:"

    fun isContextBound(value: String): Boolean = value.startsWith(PREFIX_V2)

    /** True when a metadata value still needs the unlock-time legacy migration. */
    fun requiresMetadataMigration(value: String): Boolean = !isContextBound(value)

    /** Encrypts a caller-supplied plaintext value into the current context-bound format. */
    fun encrypt(value: String, context: String): String {
        return PREFIX_V2 + CryptoManager.encryptString(
            SessionManager.requireKey(),
            value,
            aad(context)
        )
    }

    /** Upgrades a stored plaintext/v1 metadata value without double-encrypting current v2 data. */
    fun migrate(value: String, context: String): String {
        if (isContextBound(value)) return value
        val plaintext = if (value.startsWith(PREFIX_V1)) {
            CryptoManager.decryptString(SessionManager.requireKey(), value.removePrefix(PREFIX_V1))
        } else {
            value
        }
        return encrypt(plaintext, context)
    }

    /**
     * Decrypts metadata written by a released encryption format. Plaintext metadata is deliberately
     * not accepted here: only [migrate] may read it, so a failed legacy migration cannot become a
     * permanent silent plaintext compatibility mode.
     */
    fun decrypt(value: String, context: String): String = when {
        value.startsWith(PREFIX_V2) ->
            CryptoManager.decryptString(
                SessionManager.requireKey(),
                value.removePrefix(PREFIX_V2),
                aad(context)
            )
        value.startsWith(PREFIX_V1) ->
            CryptoManager.decryptString(SessionManager.requireKey(), value.removePrefix(PREFIX_V1))
        else -> throw VaultDataCorruptionException("Unencrypted metadata requires migration")
    }

    /** Encrypts a password/note field. Unlike metadata, plaintext is never accepted on decrypt. */
    fun encryptSecret(value: String, context: String): String =
        PREFIX_V2 + CryptoManager.encryptString(SessionManager.requireKey(), value, aad(context))

    /** Reads current context-bound secrets and the unprefixed AES-GCM format used by older builds. */
    fun decryptSecret(value: String, context: String): String =
        if (value.startsWith(PREFIX_V2)) {
            CryptoManager.decryptString(
                SessionManager.requireKey(),
                value.removePrefix(PREFIX_V2),
                aad(context)
            )
        } else {
            CryptoManager.decryptString(SessionManager.requireKey(), value)
        }

    fun migrateSecret(value: String, context: String): String =
        if (isContextBound(value)) value else encryptSecret(decryptSecret(value, context), context)

    /**
     * Password history is a separate record from the current credential. Keep its envelope
     * versioned so older history values, which reused the credential-password context, remain
     * readable only long enough to be migrated after a successful unlock.
     */
    fun encryptHistorySecret(value: String, credentialId: String, historyId: String): String =
        PREFIX_V3_HISTORY + CryptoManager.encryptString(
            SessionManager.requireKey(),
            value,
            aad(historyContext(credentialId, historyId))
        )

    fun decryptHistorySecret(value: String, credentialId: String, historyId: String): String =
        if (value.startsWith(PREFIX_V3_HISTORY)) {
            CryptoManager.decryptString(
                SessionManager.requireKey(),
                value.removePrefix(PREFIX_V3_HISTORY),
                aad(historyContext(credentialId, historyId))
            )
        } else {
            // v1/v2 history copied the live credential's password envelope. Do not use this
            // fallback for v3: a v3 row must authenticate against its own immutable history id.
            decryptSecret(value, "credential:$credentialId:password")
        }

    fun migrateHistorySecret(value: String, credentialId: String, historyId: String): String =
        if (value.startsWith(PREFIX_V3_HISTORY)) value else
            encryptHistorySecret(
                decryptHistorySecret(value, credentialId, historyId),
                credentialId,
                historyId
            )

    private fun aad(context: String): String {
        require(context.isNotBlank()) { "Encrypted field context is required" }
        require(context.length <= 512) { "Encrypted field context is too large" }
        return AAD_DOMAIN + context
    }

    private fun historyContext(credentialId: String, historyId: String): String {
        require(credentialId.isNotBlank()) { "Credential id is required" }
        require(historyId.isNotBlank()) { "History id is required" }
        return "history:$historyId:credential:$credentialId:password"
    }
}

class VaultDataCorruptionException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)
