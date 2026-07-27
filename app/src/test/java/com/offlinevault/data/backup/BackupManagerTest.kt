package com.offlinevault.data.backup

import com.offlinevault.data.dao.PasswordDao
import com.offlinevault.data.dao.VaultDao
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.data.model.PasswordHistoryEntity
import com.offlinevault.data.model.VaultEntity
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.SessionManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class BackupManagerTest {
    private lateinit var passwordDao: InMemoryPasswordDao
    private lateinit var vaultRepository: VaultRepository
    private lateinit var passwordRepository: PasswordRepository
    private lateinit var manager: BackupManager

    @Before fun setUp() {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        passwordDao = InMemoryPasswordDao()
        vaultRepository = VaultRepository(InMemoryVaultDao())
        passwordRepository = PasswordRepository(passwordDao)
        manager = BackupManager(vaultRepository, passwordRepository)
    }

    @After fun tearDown() {
        SessionManager.lock()
    }

    @Test fun encryptedStreamingBackupRoundTripsEmptyAndPopulatedVaults() = runBlocking {
        val emptyVault = vaultRepository.create("空密码库", "lock")
        val emptyBackup = manager.buildEncryptedJsonBackup("backup-pass")
        assertTrue(manager.validateEncryptedJsonBackup(emptyBackup, "backup-pass"))
        assertFalse(manager.validateEncryptedJsonBackup(emptyBackup, "wrong-pass"))

        passwordRepository.save(
            id = null,
            vaultId = emptyVault.id,
            title = "示例",
            username = "user@example.com",
            password = "复杂密码!123",
            url = "https://example.com",
            tags = listOf("工作,重要", "邮箱"),
            note = "多行\n敏感备注"
        )
        val populatedBackup = manager.buildEncryptedJsonBackup("backup-pass")

        assertTrue(manager.validateEncryptedJsonBackup(populatedBackup, "backup-pass"))
        val preview = manager.previewJsonBackup(populatedBackup, "backup-pass")
        assertEquals(1, preview.totalItems)
        assertEquals(1, preview.duplicateItems)
        assertEquals(0, preview.invalidItems)
    }

    @Test fun overwriteImportAccountsForDuplicateRowsWithinCsv() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        val csv = """
            name,url,username,password
            Example,https://example.com,user,secret
            Example,https://example.com,user,secret
        """.trimIndent()

        val preview = manager.previewChromeCsv(csv, vault.id)
        assertEquals(2, preview.totalItems)
        assertEquals(1, preview.newItems)
        assertEquals(1, preview.duplicateItems)

        val result = manager.importChromeCsv(csv, vault.id, ImportConflictStrategy.OVERWRITE)
        assertEquals(1, result.imported)
        assertEquals(1, result.skippedDuplicates)
        assertEquals(0, result.updated)
        assertEquals(0, result.failed)
        assertEquals(2, result.imported + result.skippedDuplicates + result.updated + result.failed)
        assertEquals(1, passwordDao.getPasswordsByVaultIdOnce(vault.id).size)
    }

    @Test fun invalidCsvRowDoesNotDiscardValidNeighbour() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        val csv = """
            name,url,username,password
            Invalid,https://invalid.example,,
            Valid,https://valid.example,user,secret
        """.trimIndent()

        val result = manager.importChromeCsv(csv, vault.id)

        assertEquals(1, result.imported)
        assertEquals(1, result.failed)
        assertEquals(0, result.skippedDuplicates)
        assertEquals(2, result.imported + result.skippedDuplicates + result.updated + result.failed)
        assertEquals(1, passwordDao.getPasswordsByVaultIdOnce(vault.id).size)
    }

    private class InMemoryVaultDao : VaultDao {
        private val rows = MutableStateFlow<List<VaultEntity>>(emptyList())

        override suspend fun insert(vault: VaultEntity) {
            rows.value = rows.value.filterNot { it.id == vault.id } + vault
        }

        override suspend fun update(vault: VaultEntity) = insert(vault)

        override suspend fun delete(vault: VaultEntity) {
            rows.value = rows.value.filterNot { it.id == vault.id }
        }

        override suspend fun getById(id: String): VaultEntity? = rows.value.firstOrNull { it.id == id }
        override fun getAllVaults(): Flow<List<VaultEntity>> = rows
        override suspend fun getAllVaultsOnce(): List<VaultEntity> = rows.value
        override suspend fun firstVault(): VaultEntity? = rows.value.firstOrNull()
        override suspend fun migrateNameIfUnchanged(
            id: String,
            oldName: String,
            newName: String
        ): Int = 0
    }

    private class InMemoryPasswordDao : PasswordDao {
        private val rows = MutableStateFlow<List<PasswordEntity>>(emptyList())
        private val history = MutableStateFlow<List<PasswordHistoryEntity>>(emptyList())

        override suspend fun insert(item: PasswordEntity) {
            rows.value = rows.value.filterNot { it.id == item.id } + item
        }

        override suspend fun insertAll(items: List<PasswordEntity>) {
            val ids = items.mapTo(hashSetOf()) { it.id }
            rows.value = rows.value.filterNot { it.id in ids } + items
        }

        override suspend fun update(item: PasswordEntity) = insert(item)

        override suspend fun delete(item: PasswordEntity) {
            rows.value = rows.value.filterNot { it.id == item.id }
            history.value = history.value.filterNot { it.passwordId == item.id }
        }

        override suspend fun getById(id: String): PasswordEntity? = rows.value.firstOrNull { it.id == id }
        override fun observeById(id: String): Flow<PasswordEntity?> =
            rows.map { list -> list.firstOrNull { it.id == id } }

        override fun getPasswordsByVaultId(vaultId: String): Flow<List<PasswordEntity>> =
            rows.map { list ->
                list.filter { it.vaultId == vaultId && it.deletedAt == 0L }
                    .sortedByDescending { it.updatedAt }
            }

        override suspend fun getPasswordsByVaultIdOnce(vaultId: String): List<PasswordEntity> =
            rows.value.filter { it.vaultId == vaultId && it.deletedAt == 0L }

        override suspend fun getAllOnce(): List<PasswordEntity> =
            rows.value.filter { it.deletedAt == 0L }

        override suspend fun getAllIncludingTrashedOnce(): List<PasswordEntity> = rows.value
        override fun observeTrashed(): Flow<List<PasswordEntity>> =
            rows.map { list -> list.filter { it.deletedAt > 0L } }

        override suspend fun softDelete(id: String, deletedAt: Long) {
            rows.value = rows.value.map { if (it.id == id) it.copy(deletedAt = deletedAt) else it }
        }

        override suspend fun softDeleteMany(ids: List<String>, deletedAt: Long) {
            val selected = ids.toSet()
            rows.value = rows.value.map { if (it.id in selected) it.copy(deletedAt = deletedAt) else it }
        }

        override suspend fun setFavorite(id: String, favorite: Boolean) {
            rows.value = rows.value.map { if (it.id == id) it.copy(favorite = favorite) else it }
        }

        override suspend fun restore(id: String) = softDelete(id, 0L)

        override suspend fun purgeTrashedOlderThan(cutoff: Long) {
            rows.value = rows.value.filterNot { it.deletedAt > 0L && it.deletedAt < cutoff }
        }

        override suspend fun emptyTrash() {
            rows.value = rows.value.filterNot { it.deletedAt > 0L }
        }

        override suspend fun insertHistory(entry: PasswordHistoryEntity) {
            history.value = history.value + entry
        }

        override suspend fun migrateHistoryEncryptionIfUnchanged(
            id: String,
            oldEncryptedPassword: String,
            newEncryptedPassword: String
        ): Int = 0

        override fun historyCount(passwordId: String): Flow<Int> =
            history.map { list -> list.count { it.passwordId == passwordId } }

        override suspend fun historyForOnce(passwordId: String): List<PasswordHistoryEntity> =
            history.value.filter { it.passwordId == passwordId }

        override suspend fun allHistoryOnce(): List<PasswordHistoryEntity> = history.value

        override suspend fun pruneHistory(passwordId: String, keep: Int) {
            val retained = history.value.filter { it.passwordId == passwordId }
                .sortedByDescending { it.changedAt }
                .take(keep)
                .mapTo(hashSetOf()) { it.id }
            history.value = history.value.filter { it.passwordId != passwordId || it.id in retained }
        }

        override suspend fun migrateEncryptionIfUnchanged(
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
        ): Int = 0
    }
}
