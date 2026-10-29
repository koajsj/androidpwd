package com.offlinevault.data.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.data.model.PasswordHistoryEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface PasswordDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(item: PasswordEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(items: List<PasswordEntity>)

    @Update
    suspend fun update(item: PasswordEntity)

    @Transaction
    suspend fun updateBatch(items: List<PasswordEntity>) {
        items.forEach { update(it) }
    }

    @Transaction
    suspend fun softDeleteBatch(ids: List<String>, deletedAt: Long): Int =
        ids.chunked(900).sumOf { softDeleteMany(it, deletedAt) }

    /** Updates a credential and its previous-password history as one atomic operation. */
    @Transaction
    suspend fun updateWithHistory(
        item: PasswordEntity,
        historyEntry: PasswordHistoryEntity?,
        historyKeep: Int
    ) {
        if (historyEntry != null) {
            insertHistory(historyEntry)
            pruneHistory(item.id, historyKeep)
        }
        update(item)
    }

    @Delete
    suspend fun delete(item: PasswordEntity)

    @Query("SELECT * FROM passwords WHERE id = :id")
    suspend fun getById(id: String): PasswordEntity?

    @Query("SELECT * FROM passwords WHERE id = :id")
    fun observeById(id: String): Flow<PasswordEntity?>

    // Active (non-trashed) rows only — deletedAt = 0.
    @Query("SELECT * FROM passwords WHERE vaultId = :vaultId AND deletedAt = 0 ORDER BY updatedAt DESC")
    fun getPasswordsByVaultId(vaultId: String): Flow<List<PasswordEntity>>

    @Query("SELECT * FROM passwords WHERE vaultId = :vaultId AND deletedAt = 0")
    suspend fun getPasswordsByVaultIdOnce(vaultId: String): List<PasswordEntity>

    @Query("SELECT * FROM passwords WHERE deletedAt = 0")
    suspend fun getAllOnce(): List<PasswordEntity>

    /** Includes recycle-bin rows so legacy encryption migration cannot leave them in plaintext. */
    @Query("SELECT * FROM passwords")
    suspend fun getAllIncludingTrashedOnce(): List<PasswordEntity>

    // ---- Recycle bin (soft delete) ----

    @Query("SELECT * FROM passwords WHERE deletedAt > 0 ORDER BY deletedAt DESC")
    fun observeTrashed(): Flow<List<PasswordEntity>>

    /** Only active credentials may enter the recycle bin; a repeated delete must not extend retention. */
    @Query("UPDATE passwords SET deletedAt = :deletedAt WHERE id = :id AND deletedAt = 0")
    suspend fun softDelete(id: String, deletedAt: Long): Int

    @Query("UPDATE passwords SET deletedAt = :deletedAt WHERE id IN (:ids) AND deletedAt = 0")
    suspend fun softDeleteMany(ids: List<String>, deletedAt: Long): Int

    @Query("UPDATE passwords SET favorite = :favorite WHERE id = :id")
    suspend fun setFavorite(id: String, favorite: Boolean)

    @Query("UPDATE passwords SET deletedAt = 0 WHERE id = :id")
    suspend fun restore(id: String)

    /** Permanently removes trashed rows older than [cutoff]; active rows are never touched. */
    @Query("DELETE FROM passwords WHERE deletedAt > 0 AND deletedAt < :cutoff")
    suspend fun purgeTrashedOlderThan(cutoff: Long)

    @Query("DELETE FROM passwords WHERE deletedAt > 0")
    suspend fun emptyTrash()

    // ---- Password history ----

    @Insert
    suspend fun insertHistory(entry: PasswordHistoryEntity)

    @Query(
        "UPDATE password_history SET encryptedPassword = :newEncryptedPassword " +
            "WHERE id = :id AND encryptedPassword = :oldEncryptedPassword"
    )
    suspend fun migrateHistoryEncryptionIfUnchanged(
        id: String,
        oldEncryptedPassword: String,
        newEncryptedPassword: String
    ): Int

    @Query("SELECT COUNT(*) FROM password_history WHERE passwordId = :passwordId")
    fun historyCount(passwordId: String): Flow<Int>

    @Query("SELECT * FROM password_history WHERE passwordId = :passwordId ORDER BY changedAt DESC")
    suspend fun historyForOnce(passwordId: String): List<PasswordHistoryEntity>

    /** Raw history rows for the unlock-time integrity sweep. */
    @Query("SELECT * FROM password_history")
    suspend fun allHistoryOnce(): List<PasswordHistoryEntity>

    /** Keeps only the [keep] most-recent history rows for a credential, deleting older ones. */
    @Query(
        "DELETE FROM password_history WHERE passwordId = :passwordId AND id NOT IN (" +
            "SELECT id FROM password_history WHERE passwordId = :passwordId " +
            "ORDER BY changedAt DESC LIMIT :keep)"
    )
    suspend fun pruneHistory(passwordId: String, keep: Int)

    @Query(
        "UPDATE passwords SET title = :newTitle, username = :newUsername, " +
            "encryptedPassword = :newPassword, url = :newUrl, tags = :newTags, " +
            "encryptedNote = :newNote WHERE id = :id AND title = :oldTitle " +
            "AND username = :oldUsername AND encryptedPassword = :oldPassword " +
            "AND url = :oldUrl AND tags = :oldTags AND encryptedNote = :oldNote"
    )
    suspend fun migrateEncryptionIfUnchanged(
        id: String,
        oldTitle: String,
        oldUsername: String,
        oldPassword: String,
        oldUrl: String,
        oldTags: String,
        oldNote: String,
        newTitle: String,
        newUsername: String,
        newPassword: String,
        newUrl: String,
        newTags: String,
        newNote: String
    ): Int

}
