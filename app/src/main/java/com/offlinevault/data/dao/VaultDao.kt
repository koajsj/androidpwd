package com.offlinevault.data.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.offlinevault.data.model.VaultEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface VaultDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(vault: VaultEntity)

    @Update
    suspend fun update(vault: VaultEntity)

    @Delete
    suspend fun delete(vault: VaultEntity)

    @Query("SELECT * FROM vaults WHERE id = :id")
    suspend fun getById(id: String): VaultEntity?

    @Query("SELECT * FROM vaults ORDER BY updatedAt DESC")
    fun getAllVaults(): Flow<List<VaultEntity>>

    @Query("SELECT * FROM vaults ORDER BY updatedAt DESC")
    suspend fun getAllVaultsOnce(): List<VaultEntity>

    @Query("SELECT * FROM vaults ORDER BY updatedAt DESC LIMIT 1")
    suspend fun firstVault(): VaultEntity?

    @Query("UPDATE vaults SET name = :newName WHERE id = :id AND name = :oldName")
    suspend fun migrateNameIfUnchanged(id: String, oldName: String, newName: String): Int
}
