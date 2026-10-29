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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class BackupManagerTest {
    private suspend fun importJsonAndAcknowledge(content: String, backupPassword: String,
        strategy: ImportConflictStrategy = ImportConflictStrategy.SKIP): ImportResult =
        manager.importJsonBackup(content, backupPassword, strategy).also(manager::acknowledgeImportResult)

    private suspend fun importCsvAndAcknowledge(content: String, targetVaultId: String,
        strategy: ImportConflictStrategy = ImportConflictStrategy.SKIP): ImportResult =
        manager.importChromeCsv(content, targetVaultId, strategy).also(manager::acknowledgeImportResult)

    @Test fun completedImportBlocksOtherEntryPointsUntilItsOwnReceiptIsDelivered() = runBlocking {
        val csv = "name,url,username,password\nSynthetic,https://synthetic.example,user,synthetic-secret\n"
        val first = manager.importChromeCsv(csv, "", ImportConflictStrategy.KEEP_BOTH)
        assertEquals(1, first.imported)
        assertTrue(manager.importJsonBackup("{}", "synthetic-backup").errors.single().contains("核对"))
        assertEquals(0, manager.importChromeCsv(csv, "", ImportConflictStrategy.KEEP_BOTH).imported)
        manager.acknowledgeImportResult(first)
        val second = manager.importChromeCsv(csv, "", ImportConflictStrategy.KEEP_BOTH)
        assertEquals(1, second.imported)
        manager.acknowledgeImportResult(first) // a late acknowledgement cannot clear the second receipt
        assertEquals(0, manager.importChromeCsv(csv, "", ImportConflictStrategy.KEEP_BOTH).imported)
        assertEquals(2, passwordDao.getAllOnce().size)
        manager.acknowledgeImportResult(second)
    }
    @Test fun unacknowledgedImportCannotBeReplayedAcrossEntryPointsOrClearedByAnOldSession() = runBlocking {
        val generation = SessionManager.requireActiveSession()
        manager.requireImportResultReview(generation)
        val csv = "name,url,username,password\nSynthetic,https://synthetic.example,user,synthetic-secret\n"
        assertTrue(manager.importJsonBackup("{}", "synthetic-backup").errors.single().contains("核对"))
        assertEquals(0, manager.importChromeCsv(csv, "", ImportConflictStrategy.KEEP_BOTH).imported)
        assertEquals(0, passwordDao.getAllOnce().size)
        val raw = SessionManager.requireKey().encoded
        val sameKey = try { CryptoManager.keyFromBytes(raw) } finally { raw.fill(0) }
        SessionManager.lock()
        SessionManager.unlock(sameKey)
        assertEquals(1, manager.importChromeCsv(csv, "", ImportConflictStrategy.KEEP_BOTH).imported)
        manager.requireImportResultReview(SessionManager.requireActiveSession())
        manager.requireImportResultReview(generation) // a late callback cannot clear a newer guard
        assertEquals(0, manager.importChromeCsv(csv, "", ImportConflictStrategy.KEEP_BOTH).imported)
        assertEquals(1, passwordDao.getAllOnce().size)
    }
    @Test fun customFieldsRoundTripAndWrongRecordBindingAreEnforced() = runBlocking {
        val vault = vaultRepository.create("Synthetic", "lock")
        val fields = listOf(com.offlinevault.data.model.CustomField(label = "Recovery", value = "synthetic-recovery-code"),
            com.offlinevault.data.model.CustomField(label = "OTP", value = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", type = com.offlinevault.data.model.CustomFieldType.TOTP))
        val id = passwordRepository.save(null, vault.id, "Synthetic", "user", "secret", "", emptyList(), "", customFields = fields)
        val stored = requireNotNull(passwordDao.getById(id))
        assertTrue(!stored.encryptedCustomFields.contains("synthetic-recovery-code"))
        assertEquals(fields, passwordRepository.getDecrypted(id)?.customFields)
        assertThrows(Exception::class.java) {
            EncryptedField.decryptSecret(stored.encryptedCustomFields, EncryptedField.customFieldsContext("other", vault.id))
        }
        assertThrows(Exception::class.java) {
            EncryptedField.decryptSecret(stored.encryptedCustomFields, EncryptedField.customFieldsContext(id, "other-vault"))
        }
        assertTrue(passwordRepository.allDecryptedSkippingCorrupt(includeExtras = false).all { it.customFields.isEmpty() && it.note.isEmpty() })
        val encrypted = manager.buildEncryptedJsonBackup("SyntheticBackupPassword")
        val wrapper = com.google.gson.JsonParser.parseString(encrypted).asJsonObject
        assertEquals(2, wrapper["version"].asInt)
        assertEquals("", wrapper["integrityHash"].asString)
        assertEquals(0, manager.previewJsonBackup(encrypted, "SyntheticBackupPassword").invalidItems)
        val csv = manager.buildCsvForVault(vault.id)
        val csvResult = importCsvAndAcknowledge(csv, "", ImportConflictStrategy.KEEP_BOTH)
        assertEquals(1, csvResult.imported)
        assertTrue(passwordRepository.allDecryptedSkippingCorrupt().all { it.customFields == fields })
        assertThrows(IllegalArgumentException::class.java) { runBlocking { manager.buildCsvForVault(vault.id, true) } }
        SessionManager.lock()
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val restoredRepository = PasswordRepository(InMemoryPasswordDao())
        val otherManager = BackupManager(VaultRepository(InMemoryVaultDao()), restoredRepository)
        assertEquals(1, otherManager.importJsonBackup(encrypted, "SyntheticBackupPassword").imported)
        assertEquals(fields, restoredRepository.allDecryptedSkippingCorrupt().single().customFields)
    }

    @Test fun unsupportedBackupVersionsFailBeforeAuthenticationWork() = runBlocking {
        assertThrows(IllegalArgumentException::class.java) { runBlocking {
            manager.previewJsonBackup("""{"format":"offline-vault-backup","version":99,"encrypted":true,"salt":"x","data":"x"}""", "Synthetic")
        } }
        Unit
    }

    @Test fun oversizedJsonExportCannotProduceAnUnrestorableBackup() = runBlocking {
        val vault = vaultRepository.create("Synthetic", "lock")
        val note = "x".repeat(128 * 1024)
        val row = com.offlinevault.data.repository.DecryptedPassword("", vault.id, "Synthetic", "u", "synthetic", "", emptyList(), note, 50, 0, 0)
        passwordRepository.importDecrypted(vault.id, List(64) { row })
        assertThrows(IllegalArgumentException::class.java) { runBlocking { manager.buildEncryptedJsonBackup("SyntheticBackupPassword") } }
        Unit
    }

    @Test fun exportsRejectFieldsThatCannotBeRestoredInsteadOfSilentlyLosingRecords() = runBlocking {
        val vault = vaultRepository.create("Synthetic", "lock")
        passwordRepository.save(null, vault.id, "x".repeat(513), "u", "synthetic", "", emptyList(), "")
        assertThrows(IllegalArgumentException::class.java) { runBlocking { manager.buildEncryptedJsonBackup("SyntheticBackupPassword") } }
        assertThrows(IllegalArgumentException::class.java) { runBlocking { manager.buildCsvForVault(vault.id) } }
        assertEquals(1, passwordRepository.decryptedForVault(vault.id).size)
    }

    @Test fun usernameCaseAndWwwAliasesNeverOverwriteOtherCredentials() = runBlocking {
        val vault = vaultRepository.create("Synthetic", "lock")
        passwordRepository.save(null, vault.id, "Original", "User", "first", "https://example.com", emptyList(), "")
        val csv = "name,url,username,password\nSecond,https://example.com,user,second\nThird,https://www.example.com,User,third"
        assertEquals(2, importCsvAndAcknowledge(csv, vault.id, ImportConflictStrategy.OVERWRITE).imported)
        assertEquals(3, passwordRepository.decryptedForVault(vault.id).size)
    }

    @Test fun nativeAppImportDeduplicatesOnlyTheExactPackage() = runBlocking {
        val vault = vaultRepository.create("Synthetic", "lock")
        passwordRepository.upsertFromAutofill(vault.id, "androidapp://com.Example.App", "user", "old")
        val csv = "name,url,username,password\nExact,androidapp://com.Example.App,user,new\nOther,androidapp://com.example.app,user,other"
        val result = importCsvAndAcknowledge(csv, vault.id, ImportConflictStrategy.OVERWRITE)
        assertEquals(1, result.updated)
        assertEquals(1, result.imported)
    }

    @Test fun legacyV1BackupWithChecksumRemainsReadable() = runBlocking {
        val vault = vaultRepository.create("Synthetic", "lock")
        val plain = com.google.gson.Gson().toJson(BackupData(listOf(BackupVault(vault.id, vault.name, vault.icon)),
            listOf(BackupItem(vault.id, "Synthetic", "u", "synthetic", "https://example.test", emptyList(), ""))))
        val salt = CryptoManager.newSalt()
        val key = CryptoManager.deriveKey("SyntheticBackupPassword".toCharArray(), salt, 100_000)
        val bytes = plain.toByteArray()
        try {
            val legacy = EncryptedBackup(version = 1, salt = CryptoManager.encode(salt),
                data = CryptoManager.encryptString(key, plain), iterations = 100_000,
                integrityHash = CryptoManager.sha256Hex(bytes))
            assertEquals(1, manager.previewJsonBackup(com.google.gson.Gson().toJson(legacy), "SyntheticBackupPassword").totalItems)
        } finally { bytes.fill(0); salt.fill(0); CryptoManager.destroyKey(key) }
    }

    @Test fun batchMetadataChangesRejectOtherVaultsAndLockedSessions() = runBlocking {
        val first = vaultRepository.create("First", "lock")
        val second = vaultRepository.create("Second", "lock")
        val a = passwordRepository.save(null, first.id, "A", "u", "p", "", emptyList(), "")
        val b = passwordRepository.save(null, second.id, "B", "u", "p", "", emptyList(), "")
        assertThrows(IllegalArgumentException::class.java) { runBlocking { passwordRepository.updateMany(first.id, setOf(a, b), true) } }
        assertTrue(!requireNotNull(passwordRepository.getDecrypted(a)).favorite)
        assertEquals(1, passwordRepository.updateMany(first.id, setOf(a), true, listOf("Synthetic")))
        assertEquals(listOf("Synthetic"), passwordRepository.getDecrypted(a)?.tags)
        SessionManager.lock()
        assertThrows(com.offlinevault.security.VaultLockedException::class.java) { runBlocking { passwordRepository.updateMany(first.id, setOf(a), false) } }
        Unit
    }
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

    @Test fun editingADeletedCredentialMustNotCreateOrModifyAnotherRecord() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        val id = passwordRepository.save(null, vault.id, "Example", "user", "original",
            "", emptyList(), "")
        passwordRepository.deleteById(id)
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                passwordRepository.save(id, vault.id, "Example", "user", "changed", "", emptyList(), "")
            }
        }
        assertEquals("original", passwordRepository.getDecrypted(id)?.password)
        passwordRepository.permanentlyDelete(id)
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                passwordRepository.save(id, vault.id, "Example", "user", "changed", "", emptyList(), "")
            }
        }
        assertTrue(passwordDao.getAllIncludingTrashedOnce().isEmpty())
    }

    @Test fun detailObservationCanBeDecryptedWithoutDoubleDecryptingMetadata() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        val id = passwordRepository.save(null, vault.id, "标题", "user", "secret",
            "https://example.com", listOf("工作"), "note")
        val observed = requireNotNull(passwordRepository.observe(id).first())
        val detail = passwordRepository.decryptForActiveSession(observed)
        assertEquals("标题", detail.title)
        assertEquals("user", detail.username)
        assertEquals("secret", detail.password)
        assertEquals("note", detail.note)
        SessionManager.lock()
        assertEquals(null, passwordRepository.observe(id).first())
    }

    @Test fun csvImportPreservesSignificantPasswordWhitespace() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        val csv = "name,url,username,password\nExample,https://example.com,user,\"  secret  \""
        val result = importCsvAndAcknowledge(csv, vault.id)
        assertEquals(1, result.imported)
        assertEquals("  secret  ", passwordRepository.decryptedForVault(vault.id).single().password)
    }

    @Test fun duplicateDetectionDoesNotTrimPasswordsForAccountsWithoutUsernames() = runBlocking {
        val vault = vaultRepository.create("个人", "lock")
        passwordRepository.save(null, vault.id, "Example", "", "secret", "https://example.com", emptyList(), "")
        val csv = "name,url,username,password\nExample,https://example.com,,\" secret \""
        assertEquals(1, manager.previewChromeCsv(csv, vault.id).newItems)
        assertEquals(1, importCsvAndAcknowledge(csv, vault.id).imported)
        assertEquals(2, passwordRepository.decryptedForVault(vault.id).size)
    }

    @Test fun encryptedStreamingBackupRoundTripsEmptyAndPopulatedVaults() = runBlocking {
        val emptyVault = vaultRepository.create("空密码库", "lock")
        val emptyBackup = manager.buildEncryptedJsonBackup("backup-pass")
        assertEquals(0, manager.previewJsonBackup(emptyBackup, "backup-pass").totalItems)

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

    @Test fun keepBothImportDoesNotReadExistingCredentials() = runBlocking {
        val vault = vaultRepository.create("Synthetic", "lock")
        val noReads = object : PasswordDao by passwordDao {
            override suspend fun getPasswordsByVaultIdOnce(vaultId: String): List<PasswordEntity> =
                error("KEEP_BOTH must not query or decrypt existing credentials")
        }
        val importer = BackupManager(vaultRepository, PasswordRepository(noReads))
        val result = importer.importChromeCsv(
            "name,url,username,password\nExample,https://example.com,user,synthetic",
            vault.id, ImportConflictStrategy.KEEP_BOTH
        )
        assertEquals(1, result.imported)
        assertEquals(0, result.failed)
        assertEquals("synthetic", passwordRepository.getDecrypted(passwordDao.getAllOnce().single().id)?.password)
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

        val result = importCsvAndAcknowledge(csv, vault.id, ImportConflictStrategy.OVERWRITE)
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

        val result = importCsvAndAcknowledge(csv, vault.id, ImportConflictStrategy.SKIP)
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
        val result = importJsonAndAcknowledge(plainJson, "backup-pass")
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

        val result = importCsvAndAcknowledge(csv, vault.id)

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

        override suspend fun touch(id: String, updatedAt: Long) {
            rows.value = rows.value.map { if (it.id == id) it.copy(updatedAt = updatedAt) else it }
        }

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
