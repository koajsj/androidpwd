package com.offlinevault.data.backup

/** Plain transfer objects used for JSON backup serialization (via Gson). */
data class BackupVault(
    val id: String,
    val name: String,
    val icon: String
)

data class BackupItem(
    val vaultId: String,
    val title: String,
    val username: String,
    val password: String,
    val url: String,
    val tags: List<String>,
    val note: String,
    // Default keeps older backups (which lack this field) importable.
    val favorite: Boolean = false,
    val customFields: List<com.offlinevault.data.model.CustomField>? = null
)

data class BackupData(
    val vaults: List<BackupVault>,
    val items: List<BackupItem>
)

/** On-disk wrapper for an ENCRYPTED JSON backup. [data] is Base64(IV || ciphertext). */
data class EncryptedBackup(
    val format: String = "offline-vault-backup",
    val version: Int = 1,
    val encrypted: Boolean = true,
    val salt: String = "",
    val data: String = "",
    /** PBKDF2 iterations used to derive the backup key. 0/absent => legacy backup. */
    val iterations: Int = 0,
    /** KDF algorithm identifier. Empty means the legacy PBKDF2-HMAC-SHA256 format. */
    val kdfVersion: String = "",
    /** Legacy v1 checksum, read-only compatibility. New backups rely on GCM authentication. */
    val integrityHash: String = ""
)

enum class ImportConflictStrategy {
    SKIP,
    OVERWRITE,
    KEEP_BOTH
}

data class ImportPreview(
    val formatLabel: String,
    val targetLabel: String,
    val totalItems: Int,
    val newItems: Int,
    val duplicateItems: Int,
    val invalidItems: Int,
    val sampleTitles: List<String>,
    val warnings: List<String> = emptyList()
)

/** Result of importing a Chrome CSV / JSON file. */
data class ImportResult(
    val imported: Int,
    val skippedDuplicates: Int,
    val failed: Int,
    val errors: List<String>,
    val updated: Int = 0,
    /** In-process acknowledgement only; never included in backup files or persisted. */
    internal val commitReceipt: Long = 0
)
