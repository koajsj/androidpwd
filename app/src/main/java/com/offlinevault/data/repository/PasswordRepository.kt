package com.offlinevault.data.repository

import com.offlinevault.autofill.OriginMatcher
import com.offlinevault.data.dao.PasswordDao
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.data.model.PasswordHistoryEntity
import com.offlinevault.data.model.TagCodec
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.EncryptedField
import com.offlinevault.security.PasswordStrengthChecker
import com.offlinevault.security.PasswordSecurityCandidate
import com.offlinevault.security.SessionManager
import com.offlinevault.security.VaultDataCorruptionException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
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

/** Minimum decrypted shape required by the on-demand password-health report. */
data class PasswordHealthCandidate(
    val id: String,
    val title: String,
    val username: String,
    val strengthScore: Int,
    val passwordFingerprint: String?,
    val passwordLength: Int,
    val characterClasses: Int,
    val isCommonWeakPassword: Boolean,
    val updatedAt: Long
) {
    fun toSecurityCandidate() = PasswordSecurityCandidate(
        id = id,
        strengthScore = strengthScore,
        passwordFingerprint = passwordFingerprint,
        passwordLength = passwordLength,
        characterClasses = characterClasses,
        isCommonWeakPassword = isCommonWeakPassword,
        updatedAt = updatedAt
    )
}

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
        passwordDao.getPasswordsByVaultId(vaultId)
            .combine(SessionManager.unlocked) { rows, unlocked ->
                if (unlocked) rows.mapNotNull(::decryptMetadataOrNull) else emptyList()
            }

    fun search(vaultId: String, query: String): Flow<List<PasswordEntity>> =
        passwordsByVault(vaultId).map { rows ->
            rows.filter { row ->
                (listOf(row.title, row.username, row.url) + TagCodec.decode(row.tags))
                    .any { it.contains(query, ignoreCase = true) }
            }
        }

    fun byTag(vaultId: String, tag: String): Flow<List<PasswordEntity>> =
        passwordsByVault(vaultId).map { rows ->
            rows.filter { row ->
                TagCodec.decode(row.tags).any { it.equals(tag, ignoreCase = true) }
            }
        }

    fun observe(id: String): Flow<PasswordEntity?> =
        passwordDao.observeById(id)
            .combine(SessionManager.unlocked) { row, unlocked ->
                if (unlocked) row?.let(::decryptMetadata) else null
            }

    /** Decrypts the password + note of an entity using the active session key. */
    fun decrypt(entity: PasswordEntity): DecryptedPassword {
        SessionManager.requireKey()
        val metadata = decryptMetadata(entity)
        val password = decryptRequired(entity.encryptedPassword, "password", entity.id)
        val note = if (entity.encryptedNote.isBlank()) "" else
            decryptRequired(entity.encryptedNote, "note", entity.id)
        return DecryptedPassword(
            id = entity.id,
            vaultId = entity.vaultId,
            title = metadata.title,
            username = metadata.username,
            password = password,
            url = metadata.url,
            tags = TagCodec.decode(metadata.tags),
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
        SessionManager.requireKey()
        val now = System.currentTimeMillis()
        val existing = id?.let { passwordDao.getById(it) }
        val entityId = existing?.id ?: UUID.randomUUID().toString()

        val entity = PasswordEntity(
            id = entityId,
            vaultId = vaultId,
            title = EncryptedField.encrypt(title.trim(), fieldContext(entityId, "title")),
            username = EncryptedField.encrypt(username.trim(), fieldContext(entityId, "username")),
            encryptedPassword = EncryptedField.encryptSecret(password, fieldContext(entityId, "password")),
            url = EncryptedField.encrypt(url.trim(), fieldContext(entityId, "url")),
            tags = EncryptedField.encrypt(
                TagCodec.encode(tags),
                fieldContext(entityId, "tags")
            ),
            encryptedNote = if (note.isBlank()) "" else
                EncryptedField.encryptSecret(note, fieldContext(entityId, "note")),
            strengthScore = PasswordStrengthChecker.evaluate(password).score,
            createdAt = existing?.createdAt ?: now,
            updatedAt = now,
            // Preserve flags on edit — they must survive a save.
            deletedAt = existing?.deletedAt ?: 0L,
            favorite = favorite ?: existing?.favorite ?: false
        )
        // Edits MUST use UPDATE, not INSERT-OR-REPLACE: REPLACE deletes the old row first, which
        // cascade-deletes its password_history. UPDATE changes the row in place and keeps history.
        if (existing != null) {
            passwordDao.updateWithHistory(
                entity,
                historyEntryIfChanged(existing, password),
                HISTORY_KEEP
            )
        } else {
            passwordDao.insert(entity)
        }
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
        passwordDao.observeTrashed()
            .combine(SessionManager.unlocked) { rows, unlocked ->
                if (unlocked) rows.mapNotNull(::decryptMetadataOrNull) else emptyList()
            }

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
        SessionManager.requireKey()
        return passwordDao.historyForOnce(passwordId).mapNotNull { row ->
            val pw = skipCorrupt {
                EncryptedField.decryptSecret(
                    row.encryptedPassword,
                    fieldContext(row.passwordId, "password")
                )
            }
                ?: return@mapNotNull null
            PasswordHistoryItem(row.id, pw, row.changedAt)
        }
    }

    /**
     * Records the soon-to-be-overwritten password into history, but only when it actually changed.
     * Reuses the existing ciphertext (same session key) so no re-encryption is needed.
     */
    private fun historyEntryIfChanged(
        existing: PasswordEntity,
        newPassword: String
    ): PasswordHistoryEntity? {
        val old = skipCorrupt {
            EncryptedField.decryptSecret(
                existing.encryptedPassword,
                fieldContext(existing.id, "password")
            )
        }
        if (old.isNullOrEmpty() || old == newPassword) return null
        return PasswordHistoryEntity(
            passwordId = existing.id,
            encryptedPassword = existing.encryptedPassword
        )
    }

    /**
     * Inserts (or updates) a credential captured by the autofill Save flow. If an entry for the
     * same target (web origin / native app) and username already exists, its password is refreshed
     * instead of creating a duplicate. [identifier] is a domain or an `androidapp://<package>` id.
     */
    suspend fun upsertFromAutofill(vaultId: String, identifier: String, username: String, password: String) {
        SessionManager.requireKey()
        val now = System.currentTimeMillis()
        val existing = passwordDao.getAllOnce().firstOrNull { entity ->
            skipCorrupt {
                val url = EncryptedField.decrypt(entity.url, fieldContext(entity.id, "url"))
                val user = EncryptedField.decrypt(entity.username, fieldContext(entity.id, "username"))
                OriginMatcher.sameTarget(url, identifier) && user.equals(username.trim(), ignoreCase = true)
            } ?: false
        }
        if (existing != null) {
            val updated = existing.copy(
                    encryptedPassword = EncryptedField.encryptSecret(
                        password,
                        fieldContext(existing.id, "password")
                    ),
                    strengthScore = PasswordStrengthChecker.evaluate(password).score,
                    updatedAt = now
                )
            passwordDao.updateWithHistory(
                updated,
                historyEntryIfChanged(existing, password),
                HISTORY_KEEP
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

    suspend fun allDecryptedSkippingCorrupt(): List<DecryptedPassword> =
        passwordDao.getAllOnce().mapNotNull {
            coroutineContext.ensureActive()
            skipCorrupt { decrypt(it) }
        }

    /**
     * Visits credentials one at a time so exports do not retain the whole decrypted vault in a
     * second list. The DAO snapshot contains ciphertext; each plaintext item becomes unreachable
     * immediately after [block] returns.
     */
    suspend fun forEachDecrypted(block: (DecryptedPassword) -> Unit): Int {
        var count = 0
        for (entity in passwordDao.getAllOnce()) {
            coroutineContext.ensureActive()
            block(decrypt(entity))
            count++
        }
        return count
    }

    /**
     * Health checks never need notes, tags or URLs. Passwords are reduced immediately to a strength
     * score and a per-run randomised fingerprint, so plaintext passwords never enter ViewModel state.
     */
    suspend fun healthCandidatesSkippingCorrupt(): List<PasswordHealthCandidate> {
        SessionManager.requireKey()
        val runPepper = CryptoManager.randomBytes(32)
        return try {
            passwordDao.getAllOnce().mapNotNull { entity ->
                coroutineContext.ensureActive()
                skipCorrupt {
                    val metadata = decryptMetadata(entity)
                    val password = decryptRequired(entity.encryptedPassword, "password", entity.id)
                    val characteristics = PasswordStrengthChecker.characteristics(password)
                    PasswordHealthCandidate(
                        id = entity.id,
                        title = metadata.title,
                        username = metadata.username,
                        strengthScore = PasswordStrengthChecker.evaluate(password).score,
                        passwordFingerprint = password
                            .takeIf { it.isNotBlank() }
                            ?.let { fingerprintForRun(it, runPepper) },
                        passwordLength = characteristics.length,
                        characterClasses = characteristics.characterClasses,
                        isCommonWeakPassword = characteristics.isCommonWeakPassword,
                        updatedAt = entity.updatedAt
                    )
                }
            }
        } finally {
            runPepper.fill(0)
        }
    }

    suspend fun decryptedForVault(vaultId: String): List<DecryptedPassword> =
        passwordDao.getPasswordsByVaultIdOnce(vaultId).map {
            coroutineContext.ensureActive()
            decrypt(it)
        }

    suspend fun decryptedForVaultSkippingCorrupt(vaultId: String): List<DecryptedPassword> =
        passwordDao.getPasswordsByVaultIdOnce(vaultId).mapNotNull {
            coroutineContext.ensureActive()
            skipCorrupt { decrypt(it) }
        }

    /**
     * Decrypts only the (cheap) URL metadata of every row, keeps the ones whose URL satisfies
     * [urlMatches], and fully decrypts the password/note for just those. Used by autofill so the
     * secrets of non-matching entries are never brought into memory. Corrupted rows are skipped.
     */
    suspend fun decryptedMatching(urlMatches: (String) -> Boolean): List<DecryptedPassword> {
        SessionManager.requireKey() // fail fast when locked
        return passwordDao.getAllOnce().mapNotNull { entity ->
            val url = skipCorrupt {
                EncryptedField.decrypt(entity.url, fieldContext(entity.id, "url"))
            } ?: return@mapNotNull null
            if (!urlMatches(url)) return@mapNotNull null
            skipCorrupt { decrypt(entity) }
        }
    }

    /** Bulk insert used by import. Each [DecryptedPassword] is encrypted before storage. */
    suspend fun importDecrypted(vaultId: String, items: List<DecryptedPassword>): Int {
        SessionManager.requireKey()
        val now = System.currentTimeMillis()
        val entities = items.map { item ->
            coroutineContext.ensureActive()
            SessionManager.requireKey()
            val entityId = UUID.randomUUID().toString()
            PasswordEntity(
                id = entityId,
                vaultId = vaultId,
                title = EncryptedField.encrypt(item.title, fieldContext(entityId, "title")),
                username = EncryptedField.encrypt(item.username, fieldContext(entityId, "username")),
                encryptedPassword = EncryptedField.encryptSecret(
                    item.password,
                    fieldContext(entityId, "password")
                ),
                url = EncryptedField.encrypt(item.url, fieldContext(entityId, "url")),
                tags = EncryptedField.encrypt(
                    TagCodec.encode(item.tags),
                    fieldContext(entityId, "tags")
                ),
                encryptedNote = if (item.note.isBlank()) "" else
                    EncryptedField.encryptSecret(item.note, fieldContext(entityId, "note")),
                strengthScore = PasswordStrengthChecker.evaluate(item.password).score,
                createdAt = now,
                updatedAt = now,
                favorite = item.favorite
            )
        }
        passwordDao.insertAll(entities)
        return entities.size
    }

    suspend fun migrateLegacyEncryption() {
        passwordDao.getAllIncludingTrashedOnce().forEach { row ->
            try {
                val migrated = row.copy(
                    title = EncryptedField.migrate(row.title, fieldContext(row.id, "title")),
                    username = EncryptedField.migrate(row.username, fieldContext(row.id, "username")),
                    encryptedPassword = EncryptedField.migrateSecret(
                        row.encryptedPassword,
                        fieldContext(row.id, "password")
                    ),
                    url = EncryptedField.migrate(row.url, fieldContext(row.id, "url")),
                    tags = EncryptedField.migrate(row.tags, fieldContext(row.id, "tags")),
                    encryptedNote = if (row.encryptedNote.isBlank()) "" else
                        EncryptedField.migrateSecret(row.encryptedNote, fieldContext(row.id, "note"))
                )
                if (migrated != row) {
                    passwordDao.migrateEncryptionIfUnchanged(
                        id = row.id,
                        oldTitle = row.title,
                        oldUsername = row.username,
                        oldPassword = row.encryptedPassword,
                        oldUrl = row.url,
                        oldTags = row.tags,
                        oldNote = row.encryptedNote,
                        newTitle = migrated.title,
                        newUsername = migrated.username,
                        newPassword = migrated.encryptedPassword,
                        newUrl = migrated.url,
                        newTags = migrated.tags,
                        newNote = migrated.encryptedNote
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Keep a damaged row isolated. The integrity sweep reports it after migration.
            }
        }
        passwordDao.allHistoryOnce().forEach { row ->
            try {
                val migrated = row.copy(
                    encryptedPassword = EncryptedField.migrateSecret(
                        row.encryptedPassword,
                        fieldContext(row.passwordId, "password")
                    )
                )
                if (migrated != row) {
                    passwordDao.migrateHistoryEncryptionIfUnchanged(
                        id = row.id,
                        oldEncryptedPassword = row.encryptedPassword,
                        newEncryptedPassword = migrated.encryptedPassword
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // The integrity sweep reports and the UI skips a damaged history entry.
            }
        }
    }

    /** Resilient variant used by list flows: returns null instead of throwing on a corrupted row. */
    private fun decryptMetadataOrNull(entity: PasswordEntity): PasswordEntity? =
        skipCorrupt { decryptMetadata(entity) }

    /**
     * Isolate corrupt rows without swallowing coroutine cancellation. `runCatching` catches
     * CancellationException too, which can make a dismissed import/list scan keep doing crypto
     * work in the background on a large vault.
     */
    private inline fun <T> skipCorrupt(block: () -> T): T? = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        null
    }

    private fun decryptMetadata(entity: PasswordEntity): PasswordEntity = try {
        entity.copy(
            title = EncryptedField.decrypt(entity.title, fieldContext(entity.id, "title")),
            username = EncryptedField.decrypt(entity.username, fieldContext(entity.id, "username")),
            url = EncryptedField.decrypt(entity.url, fieldContext(entity.id, "url")),
            tags = EncryptedField.decrypt(entity.tags, fieldContext(entity.id, "tags"))
        )
    } catch (e: Exception) {
        throw VaultDataCorruptionException("Credential metadata is corrupted: ${entity.id}", e)
    }

    private fun decryptRequired(
        value: String,
        field: String,
        id: String
    ): String = try {
        EncryptedField.decryptSecret(value, fieldContext(id, field))
    } catch (e: Exception) {
        throw VaultDataCorruptionException("Credential $field is corrupted: $id", e)
    }

    private fun fieldContext(id: String, field: String): String = "credential:$id:$field"

    /**
     * Per-run salted fingerprint supports reuse grouping without retaining plaintext passwords or
     * a stable offline-verification hash in ViewModel state.
     */
    private fun fingerprintForRun(password: String, runPepper: ByteArray): String {
        val passwordBytes = password.toByteArray(Charsets.UTF_8)
        val material = ByteArray(runPepper.size + passwordBytes.size)
        return try {
            runPepper.copyInto(material)
            passwordBytes.copyInto(material, destinationOffset = runPepper.size)
            CryptoManager.sha256Hex(material)
        } finally {
            passwordBytes.fill(0)
            material.fill(0)
        }
    }
}
