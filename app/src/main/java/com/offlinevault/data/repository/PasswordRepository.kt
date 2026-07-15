package com.offlinevault.data.repository

import com.offlinevault.autofill.OriginMatcher
import com.offlinevault.data.dao.PasswordDao
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.EncryptedField
import com.offlinevault.security.PasswordStrengthChecker
import com.offlinevault.security.SessionManager
import com.offlinevault.security.VaultDataCorruptionException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext
import java.util.UUID

/** A fully decrypted credential, used only in-memory by the UI while unlocked. */
data class DecryptedPassword(
    val id: String,
    val vaultId: String,
    val title: String,
    val username: String,
    val password: String,
    val url: String,
    val tags: List<String>,
    val note: String,
    val strengthScore: Int,
    val createdAt: Long,
    val updatedAt: Long,
    val favorite: Boolean = false
)

/** A decrypted previous password, shown in the credential's history view. */
data class PasswordHistoryItem(
    val id: String,
    val password: String,
    val changedAt: Long
)

class PasswordRepository(private val passwordDao: PasswordDao) {

    companion object {
        /** Trashed credentials are kept this many days before automatic permanent deletion. */
        const val TRASH_RETENTION_DAYS = 30

        /** How many previous passwords are retained per credential. */
        const val HISTORY_KEEP = 10
    }

    fun passwordsByVault(vaultId: String): Flow<List<PasswordEntity>> =
        // List views skip any individually corrupted row so one bad entry can't blank the whole
        // screen; the detail view still surfaces a per-item corruption error.
        passwordDao.getPasswordsByVaultId(vaultId).map { rows -> rows.mapNotNull(::decryptMetadataOrNull) }

    fun search(vaultId: String, query: String): Flow<List<PasswordEntity>> =
        passwordsByVault(vaultId).map { rows ->
            rows.filter { row ->
                listOf(row.title, row.username, row.url, row.tags)
                    .any { it.contains(query, ignoreCase = true) }
            }
        }

    fun byTag(vaultId: String, tag: String): Flow<List<PasswordEntity>> =
        passwordsByVault(vaultId).map { rows ->
            rows.filter { row ->
                row.tags.split(',').map(String::trim).any { it.equals(tag, ignoreCase = true) }
            }
        }

    fun observe(id: String): Flow<PasswordEntity?> =
        passwordDao.observeById(id).map { it?.let(::decryptMetadata) }

    /** Decrypts the password + note of an entity using the active session key. */
    fun decrypt(entity: PasswordEntity): DecryptedPassword {
        val key = SessionManager.requireKey()
        val metadata = decryptMetadata(entity)
        val password = decryptRequired(key, entity.encryptedPassword, "password", entity.id)
        val note = if (entity.encryptedNote.isBlank()) "" else
            decryptRequired(key, entity.encryptedNote, "note", entity.id)
        return DecryptedPassword(
            id = entity.id,
            vaultId = entity.vaultId,
            title = metadata.title,
            username = metadata.username,
            password = password,
            url = metadata.url,
            tags = metadata.tags.split(",").map { it.trim() }.filter { it.isNotEmpty() },
            note = note,
            strengthScore = entity.strengthScore,
            createdAt = entity.createdAt,
            updatedAt = entity.updatedAt,
            favorite = entity.favorite
        )
    }

    suspend fun getDecrypted(id: String): DecryptedPassword? =
        passwordDao.getById(id)?.let { decrypt(it) }

    /** Encrypts and stores a new or edited credential. */
    suspend fun save(
        id: String?,
        vaultId: String,
        title: String,
        username: String,
        password: String,
        url: String,
        tags: List<String>,
        note: String,
        favorite: Boolean? = null
    ): String {
        val key = SessionManager.requireKey()
        val now = System.currentTimeMillis()
        val existing = id?.let { passwordDao.getById(it) }
        if (existing != null) recordHistoryIfChanged(existing, password, key)

        val entity = PasswordEntity(
            id = existing?.id ?: UUID.randomUUID().toString(),
            vaultId = vaultId,
            title = EncryptedField.encrypt(title.trim()),
            username = EncryptedField.encrypt(username.trim()),
            encryptedPassword = CryptoManager.encryptString(key, password),
            url = EncryptedField.encrypt(url.trim()),
            tags = EncryptedField.encrypt(tags.joinToString(",") { it.trim() }.trim()),
            encryptedNote = if (note.isBlank()) "" else CryptoManager.encryptString(key, note),
            strengthScore = PasswordStrengthChecker.evaluate(password).score,
            createdAt = existing?.createdAt ?: now,
            updatedAt = now,
            // Preserve flags on edit — they must survive a save.
            deletedAt = existing?.deletedAt ?: 0L,
            favorite = favorite ?: existing?.favorite ?: false
        )
        // Edits MUST use UPDATE, not INSERT-OR-REPLACE: REPLACE deletes the old row first, which
        // cascade-deletes its password_history. UPDATE changes the row in place and keeps history.
        if (existing != null) passwordDao.update(entity) else passwordDao.insert(entity)
        return entity.id
    }

    /** Moves a credential to the recycle bin (soft delete) instead of erasing it immediately. */
    suspend fun deleteById(id: String) {
        passwordDao.softDelete(id, System.currentTimeMillis())
    }

    /** Moves several credentials to the recycle bin at once (batch delete). */
    suspend fun deleteMany(ids: List<String>) {
        if (ids.isNotEmpty()) passwordDao.softDeleteMany(ids, System.currentTimeMillis())
    }

    /** Pins/unpins a credential. Favorites sort to the top of the list. */
    suspend fun setFavorite(id: String, favorite: Boolean) {
        passwordDao.setFavorite(id, favorite)
    }

    // ---- Recycle bin -------------------------------------------------------

    /** Trashed credentials, newest deletion first. Corrupted rows are skipped, never crash the list. */
    fun trashed(): Flow<List<PasswordEntity>> =
        passwordDao.observeTrashed().map { rows -> rows.mapNotNull(::decryptMetadataOrNull) }

    suspend fun restore(id: String) {
        passwordDao.restore(id)
    }

    /** Permanently erases a single trashed (or any) row by id. */
    suspend fun permanentlyDelete(id: String) {
        passwordDao.getById(id)?.let { passwordDao.delete(it) }
    }

    suspend fun emptyTrash() {
        passwordDao.emptyTrash()
    }

    /** Auto-purge: erase trashed rows older than [retentionDays]. Called once per unlock. */
    suspend fun purgeExpiredTrash(retentionDays: Int = TRASH_RETENTION_DAYS) {
        val cutoff = System.currentTimeMillis() - retentionDays * 24L * 60 * 60 * 1000
        passwordDao.purgeTrashedOlderThan(cutoff)
    }

    // ---- Password history --------------------------------------------------

    /** Live count of stored previous passwords for a credential (for the detail-screen badge). */
    fun historyCount(passwordId: String): Flow<Int> = passwordDao.historyCount(passwordId)

    /** Decrypts the stored previous passwords for a credential, newest first. Corrupted rows skipped. */
    suspend fun history(passwordId: String): List<PasswordHistoryItem> {
        val key = SessionManager.requireKey()
        return passwordDao.historyForOnce(passwordId).mapNotNull { row ->
            val pw = runCatching { CryptoManager.decryptString(key, row.encryptedPassword) }.getOrNull()
                ?: return@mapNotNull null
            PasswordHistoryItem(row.id, pw, row.changedAt)
        }
    }

    /**
     * Records the soon-to-be-overwritten password into history, but only when it actually changed.
     * Reuses the existing ciphertext (same session key) so no re-encryption is needed.
     */
    private suspend fun recordHistoryIfChanged(existing: PasswordEntity, newPassword: String, key: javax.crypto.SecretKey) {
        val old = runCatching { CryptoManager.decryptString(key, existing.encryptedPassword) }.getOrNull()
        if (old.isNullOrEmpty() || old == newPassword) return
        passwordDao.insertHistory(
            com.offlinevault.data.model.PasswordHistoryEntity(
                passwordId = existing.id,
                encryptedPassword = existing.encryptedPassword
            )
        )
        passwordDao.pruneHistory(existing.id, HISTORY_KEEP)
    }

    /**
     * Inserts (or updates) a credential captured by the autofill Save flow. If an entry for the
     * same target (web origin / native app) and username already exists, its password is refreshed
     * instead of creating a duplicate. [identifier] is a domain or an `androidapp://<package>` id.
     */
    suspend fun upsertFromAutofill(vaultId: String, identifier: String, username: String, password: String) {
        val key = SessionManager.requireKey()
        val now = System.currentTimeMillis()
        val existing = passwordDao.getAllOnce().firstOrNull { entity ->
            runCatching {
                val url = EncryptedField.decrypt(entity.url)
                val user = EncryptedField.decrypt(entity.username)
                OriginMatcher.sameTarget(url, identifier) && user.equals(username.trim(), ignoreCase = true)
            }.getOrDefault(false)
        }
        if (existing != null) {
            recordHistoryIfChanged(existing, password, key)
            passwordDao.update(
                existing.copy(
                    encryptedPassword = CryptoManager.encryptString(key, password),
                    strengthScore = PasswordStrengthChecker.evaluate(password).score,
                    updatedAt = now
                )
            )
            return
        }
        save(
            id = null,
            vaultId = vaultId,
            title = titleFor(identifier),
            username = username.trim(),
            password = password,
            url = identifier,
            tags = emptyList(),
            note = ""
        )
    }

    private fun titleFor(identifier: String): String = when {
        identifier.startsWith(OriginMatcher.APP_SCHEME) ->
            identifier.removePrefix(OriginMatcher.APP_SCHEME).substringAfterLast('.').ifBlank { "应用" }
        else -> OriginMatcher.hostFromUrl(identifier) ?: identifier.ifBlank { "已保存" }
    }

    suspend fun allDecrypted(): List<DecryptedPassword> =
        passwordDao.getAllOnce().map {
            coroutineContext.ensureActive()
            decrypt(it)
        }

    suspend fun allDecryptedSkippingCorrupt(): List<DecryptedPassword> =
        passwordDao.getAllOnce().mapNotNull {
            coroutineContext.ensureActive()
            runCatching { decrypt(it) }.getOrNull()
        }

    suspend fun decryptedForVault(vaultId: String): List<DecryptedPassword> =
        passwordDao.getPasswordsByVaultIdOnce(vaultId).map {
            coroutineContext.ensureActive()
            decrypt(it)
        }

    suspend fun decryptedForVaultSkippingCorrupt(vaultId: String): List<DecryptedPassword> =
        passwordDao.getPasswordsByVaultIdOnce(vaultId).mapNotNull {
            coroutineContext.ensureActive()
            runCatching { decrypt(it) }.getOrNull()
        }

    /**
     * Decrypts only the (cheap) URL metadata of every row, keeps the ones whose URL satisfies
     * [urlMatches], and fully decrypts the password/note for just those. Used by autofill so the
     * secrets of non-matching entries are never brought into memory. Corrupted rows are skipped.
     */
    suspend fun decryptedMatching(urlMatches: (String) -> Boolean): List<DecryptedPassword> {
        SessionManager.requireKey() // fail fast when locked
        return passwordDao.getAllOnce().mapNotNull { entity ->
            val url = runCatching { EncryptedField.decrypt(entity.url) }.getOrNull() ?: return@mapNotNull null
            if (!urlMatches(url)) return@mapNotNull null
            runCatching { decrypt(entity) }.getOrNull()
        }
    }

    /** Bulk insert used by import. Each [DecryptedPassword] is encrypted before storage. */
    suspend fun importDecrypted(vaultId: String, items: List<DecryptedPassword>): Int {
        val key = SessionManager.requireKey()
        val now = System.currentTimeMillis()
        val entities = items.map { item ->
            coroutineContext.ensureActive()
            SessionManager.requireKey()
            PasswordEntity(
                id = UUID.randomUUID().toString(),
                vaultId = vaultId,
                title = EncryptedField.encrypt(item.title),
                username = EncryptedField.encrypt(item.username),
                encryptedPassword = CryptoManager.encryptString(key, item.password),
                url = EncryptedField.encrypt(item.url),
                tags = EncryptedField.encrypt(item.tags.joinToString(",")),
                encryptedNote = if (item.note.isBlank()) "" else CryptoManager.encryptString(key, item.note),
                strengthScore = PasswordStrengthChecker.evaluate(item.password).score,
                createdAt = now,
                updatedAt = now,
                favorite = item.favorite
            )
        }
        passwordDao.insertAll(entities)
        return entities.size
    }

    suspend fun migrateLegacyMetadata() {
        passwordDao.getAllIncludingTrashedOnce().forEach { row ->
            // Older releases could leave a mixture of legacy plaintext and encrypted metadata.
            // Encrypt fields independently: re-encrypting the already protected fields would make
            // their display value the ciphertext after the next unlock.
            val migrated = row.copy(
                title = encryptLegacyMetadata(row.title),
                username = encryptLegacyMetadata(row.username),
                url = encryptLegacyMetadata(row.url),
                tags = encryptLegacyMetadata(row.tags)
            )
            if (migrated != row) {
                passwordDao.update(migrated)
            }
        }
    }

    private fun encryptLegacyMetadata(value: String): String =
        if (EncryptedField.isEncrypted(value)) value else EncryptedField.encrypt(value)

    /** Resilient variant used by list flows: returns null instead of throwing on a corrupted row. */
    private fun decryptMetadataOrNull(entity: PasswordEntity): PasswordEntity? =
        runCatching { decryptMetadata(entity) }.getOrNull()

    private fun decryptMetadata(entity: PasswordEntity): PasswordEntity = try {
        entity.copy(
            title = EncryptedField.decrypt(entity.title),
            username = EncryptedField.decrypt(entity.username),
            url = EncryptedField.decrypt(entity.url),
            tags = EncryptedField.decrypt(entity.tags)
        )
    } catch (e: Exception) {
        throw VaultDataCorruptionException("Credential metadata is corrupted: ${entity.id}", e)
    }

    private fun decryptRequired(
        key: javax.crypto.SecretKey,
        value: String,
        field: String,
        id: String
    ): String = try {
        CryptoManager.decryptString(key, value)
    } catch (e: Exception) {
        throw VaultDataCorruptionException("Credential $field is corrupted: $id", e)
    }
}
