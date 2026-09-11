package com.offlinevault.data.backup

import com.offlinevault.data.dao.PasswordDao
import com.offlinevault.data.dao.VaultDao
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.data.model.PasswordHistoryEntity
import com.offlinevault.data.model.VaultEntity
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.EncryptedField
import com.offlinevault.security.SessionManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
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
        assertEquals(0, manager.previewJsonBackup(emptyBackup, "backup-pass").totalItems)
        assertThrows(Exception::class.java) {
            runBlocking { manager.previewJsonBackup(emptyBackup, "wrong-pass") }
        }

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

    @Test fun sameTitleAndUsernameOnDifferentHostsAreNotDuplicates() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        passwordRepository.save(
            id = null,
            vaultId = vault.id,
            title = "Google",
            username = "user@example.com",
            password = "first-password",
            url = "https://accounts.google.com",
            tags = emptyList(),
            note = ""
        )
        val csv = """
            name,url,username,password
            Google,https://mail.google.com,user@example.com,second-password
        """.trimIndent()

        val preview = manager.previewChromeCsv(csv, vault.id)
        assertEquals(1, preview.newItems)
        assertEquals(0, preview.duplicateItems)

        val result = manager.importChromeCsv(csv, vault.id, ImportConflictStrategy.SKIP)
        assertEquals(1, result.imported)
        assertEquals(0, result.skippedDuplicates)
        assertEquals(2, passwordDao.getPasswordsByVaultIdOnce(vault.id).size)
    }

    @Test fun encryptedJsonImportRejectsPlainJsonAndWrongPassword() = runBlocking {
        val plainJson = """{"vaults":[],"items":[]}"""

        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { manager.previewJsonBackup(plainJson, "backup-pass") }
        }

        val encrypted = manager.buildEncryptedJsonBackup("backup-pass")
        assertThrows(Exception::class.java) {
            runBlocking { manager.previewJsonBackup(encrypted, "incorrect-pass") }
        }
        val result = manager.importJsonBackup(plainJson, "backup-pass")
        assertEquals(0, result.imported)
        assertTrue(result.errors.single().contains("加密备份"))
    }

    @Test fun autofillUpsertOnlyUpdatesTheRequestedVault() = runBlocking {
        val firstVault = vaultRepository.create("个人", "lock")
        val secondVault = vaultRepository.create("工作", "lock")
        passwordRepository.save(
            id = null,
            vaultId = firstVault.id,
            title = "Example",
            username = "user@example.com",
            password = "first-password",
            url = "https://example.com",
            tags = emptyList(),
            note = ""
        )
        passwordRepository.save(
            id = null,
            vaultId = secondVault.id,
            title = "Example",
            username = "user@example.com",
            password = "second-password",
            url = "https://example.com",
            tags = emptyList(),
            note = ""
        )

        passwordRepository.upsertFromAutofill(
            secondVault.id,
            "example.com",
            "user@example.com",
            "updated-second-password"
        )

        assertEquals("first-password", passwordRepository.decryptedForVault(firstVault.id).single().password)
        assertEquals(
            "updated-second-password",
            passwordRepository.decryptedForVault(secondVault.id).single().password
        )
    }

    @Test fun lockedSessionRejectsAllPasswordRepositoryWrites() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        val id = passwordRepository.save(
            id = null,
            vaultId = vault.id,
            title = "Example",
            username = "user",
            password = "password",
            url = "https://example.com",
            tags = emptyList(),
            note = ""
        )
        passwordRepository.deleteById(id)
        SessionManager.lock()

        val writes = listOf<suspend () -> Unit>(
            { passwordRepository.save(null, vault.id, "new", "user", "password", "", emptyList(), "") },
            { passwordRepository.deleteById(id) },
            { passwordRepository.deleteMany(listOf(id)) },
            { passwordRepository.setFavorite(id, true) },
            { passwordRepository.restore(id) },
            { passwordRepository.permanentlyDelete(id) },
            { passwordRepository.emptyTrash() },
            { passwordRepository.purgeExpiredTrash() },
            { passwordRepository.upsertFromAutofill(vault.id, "example.com", "user", "new") },
            { passwordRepository.importDecrypted(vault.id, emptyList()) }
        )
        writes.forEach { write ->
            assertThrows(IllegalStateException::class.java) { runBlocking { write() } }
        }
        assertEquals(1, passwordDao.getAllIncludingTrashedOnce().size)
    }

    @Test fun lockedSessionRejectsAllSensitiveReads() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        val id = passwordRepository.save(
            id = null,
            vaultId = vault.id,
            title = "Example",
            username = "user",
            password = "password",
            url = "https://example.com",
            tags = emptyList(),
            note = "private"
        )
        val encrypted = requireNotNull(passwordDao.getById(id))
        SessionManager.lock()

        val reads = listOf<suspend () -> Unit>(
            { passwordRepository.getDecrypted(id) },
            { passwordRepository.decryptForActiveSession(encrypted) },
            { passwordRepository.history(id) },
            { passwordRepository.allDecryptedSkippingCorrupt() },
            { passwordRepository.healthCandidatesSkippingCorrupt() },
            { passwordRepository.decryptedForVault(vault.id) },
            { passwordRepository.decryptedMatching { true } },
            { vaultRepository.getById(vault.id) },
            { vaultRepository.allOnce() },
            { manager.buildEncryptedJsonBackup("backup-pass") }
        )
        reads.forEach { read ->
            assertThrows(IllegalStateException::class.java) { runBlocking { read() } }
        }
    }

    @Test fun legacyMetadataMigratesInPlaceBeforeStrictReads() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        val id = "legacy-credential"
        passwordDao.insert(
            PasswordEntity(
                id = id,
                vaultId = vault.id,
                title = "旧标题",
                username = "old-user",
                encryptedPassword = CryptoManager.encryptString(SessionManager.requireKey(), "old-password"),
                url = "https://legacy.example",
                tags = "旧标签",
                encryptedNote = CryptoManager.encryptString(SessionManager.requireKey(), "old-note")
            )
        )

        passwordRepository.migrateLegacyEncryption()

        val stored = requireNotNull(passwordDao.getById(id))
        assertTrue(EncryptedField.isContextBound(stored.title))
        assertTrue(EncryptedField.isContextBound(stored.username))
        assertTrue(EncryptedField.isContextBound(stored.url))
        assertTrue(EncryptedField.isContextBound(stored.tags))
        assertTrue(EncryptedField.isContextBound(stored.encryptedPassword))
        assertTrue(EncryptedField.isContextBound(stored.encryptedNote))
        assertEquals("old-password", passwordRepository.getDecrypted(id)?.password)
        assertEquals("old-note", passwordRepository.getDecrypted(id)?.note)
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

    @Test fun repeatedDeleteDoesNotExtendRecycleBinRetention() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        val id = passwordRepository.save(
            id = null,
            vaultId = vault.id,
            title = "Example",
            username = "user",
            password = "password",
            url = "https://example.com",
            tags = emptyList(),
            note = ""
        )

        passwordRepository.deleteById(id)
        val firstDeletedAt = requireNotNull(passwordDao.getById(id)).deletedAt
        passwordRepository.deleteById(id)

        assertEquals(firstDeletedAt, requireNotNull(passwordDao.getById(id)).deletedAt)
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

        override suspend fun softDelete(id: String, deletedAt: Long): Int {
            val target = rows.value.firstOrNull { it.id == id && it.deletedAt == 0L } ?: return 0
            rows.value = rows.value.map { if (it.id == id) target.copy(deletedAt = deletedAt) else it }
            return 1
        }

        override suspend fun softDeleteMany(ids: List<String>, deletedAt: Long): Int {
            val selected = rows.value
                .filter { it.id in ids && it.deletedAt == 0L }
                .mapTo(hashSetOf()) { it.id }
            rows.value = rows.value.map { if (it.id in selected) it.copy(deletedAt = deletedAt) else it }
            return selected.size
        }

        override suspend fun setFavorite(id: String, favorite: Boolean) {
            rows.value = rows.value.map { if (it.id == id) it.copy(favorite = favorite) else it }
        }

        override suspend fun restore(id: String) {
            rows.value = rows.value.map { if (it.id == id) it.copy(deletedAt = 0L) else it }
        }

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
        ): Int {
            val existing = history.value.firstOrNull {
                it.id == id && it.encryptedPassword == oldEncryptedPassword
            } ?: return 0
            history.value = history.value.map {
                if (it.id == existing.id) it.copy(encryptedPassword = newEncryptedPassword) else it
            }
            return 1
        }

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
        ): Int {
            val existing = rows.value.firstOrNull {
                it.id == id &&
                    it.title == oldTitle &&
                    it.username == oldUsername &&
                    it.encryptedPassword == oldPassword &&
                    it.url == oldUrl &&
                    it.tags == oldTags &&
                    it.encryptedNote == oldNote
            } ?: return 0
            rows.value = rows.value.map {
                if (it.id == existing.id) {
                    it.copy(
                        title = newTitle,
                        username = newUsername,
                        encryptedPassword = newPassword,
                        url = newUrl,
                        tags = newTags,
                        encryptedNote = newNote
                    )
                } else {
                    it
                }
            }
            return 1
        }
    }
}
