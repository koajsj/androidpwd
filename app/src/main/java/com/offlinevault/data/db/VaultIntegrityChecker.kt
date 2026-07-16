package com.offlinevault.data.db

import com.offlinevault.security.CryptoManager
import com.offlinevault.security.EncryptedField
import com.offlinevault.security.SessionManager

/** Result of a non-destructive vault integrity sweep performed after unlock. */
data class VaultIntegrityReport(
    val databaseHealthy: Boolean,
    val invalidVaultMetadata: Int,
    val invalidCredentials: Int,
    val invalidHistoryEntries: Int
) {
    val hasEncryptedDataIssues: Boolean
        get() = invalidVaultMetadata + invalidCredentials + invalidHistoryEntries > 0
}

/**
 * Checks both SQLite's physical structure and every AES-GCM protected record. AES-GCM already
 * authenticates each encrypted field, so a modified ciphertext fails here without turning one bad
 * row into a whole-vault lockout. This does not claim rollback protection against a rooted device.
 */
class VaultIntegrityChecker(private val database: AppDatabase) {

    suspend fun inspect(): VaultIntegrityReport {
        val databaseHealthy = runCatching {
            database.openHelper.readableDatabase.query("PRAGMA quick_check(1)").use { cursor ->
                cursor.moveToFirst() && cursor.getString(0).equals("ok", ignoreCase = true)
            }
        }.getOrDefault(false)
        if (!databaseHealthy) return VaultIntegrityReport(false, 0, 0, 0)

        val key = SessionManager.requireKey()
        val invalidVaults = database.vaultDao().getAllVaultsOnce().count { vault ->
            runCatching { EncryptedField.decrypt(vault.name) }.isFailure
        }
        val invalidCredentials = database.passwordDao().getAllIncludingTrashedOnce().count { row ->
            runCatching {
                EncryptedField.decrypt(row.title)
                EncryptedField.decrypt(row.username)
                EncryptedField.decrypt(row.url)
                EncryptedField.decrypt(row.tags)
                CryptoManager.decryptString(key, row.encryptedPassword)
                if (row.encryptedNote.isNotBlank()) {
                    CryptoManager.decryptString(key, row.encryptedNote)
                }
            }.isFailure
        }
        val invalidHistory = database.passwordDao().allHistoryOnce().count { row ->
            runCatching { CryptoManager.decryptString(key, row.encryptedPassword) }.isFailure
        }
        return VaultIntegrityReport(true, invalidVaults, invalidCredentials, invalidHistory)
    }
}
