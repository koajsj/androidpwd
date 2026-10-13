package com.offlinevault.data.db

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.lifecycle.ViewModelStore
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.data.backup.BackupManager
import com.offlinevault.data.dao.PasswordDao
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.security.VaultLockedException
import com.offlinevault.viewmodel.PasswordDetailViewModel
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.EncryptedField
import com.offlinevault.security.SessionManager
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Creates genuine historical database shapes, then opens each through the production Room builder.
 * This verifies the complete 1→2→3→4→5 path and every supported shortcut without relying on a
 * freshly-created latest-version database.
 */
@RunWith(AndroidJUnit4::class)
class MigrationTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val testDb = "migration-test.db"

    @After
    fun tearDown() {
        SessionManager.lock()
        context.deleteDatabase(testDb)
    }

    @Test
    fun allHistoricalVersionsMigrateToLatestWithoutLosingRows() = runBlocking {
        for (version in 1..4) {
            SessionManager.unlock(CryptoManager.newDataEncryptionKey())
            createHistoricalDatabase(version)
            val database = AppDatabase.openForMigrationTest(context, testDb)
            try {
                // Forces Room to run the production migration chain and validate its v5 schema.
                database.openHelper.writableDatabase
                val credential = database.passwordDao().getById("credential-$version")
                assertNotNull("v$version credential was lost", credential)
                requireNotNull(credential).also { row ->
                    assertEquals("vault-$version", row.vaultId)
                    assertEquals(0L, row.deletedAt)
                    assertFalse(row.favorite)
                }
                assertNotNull("v$version vault was lost", database.vaultDao().getById("vault-$version"))
                VaultRepository(database.vaultDao()).migrateLegacyMetadata()
                val passwordRepository = PasswordRepository(database.passwordDao())
                passwordRepository.migrateLegacyEncryption()
                val migrated = requireNotNull(database.passwordDao().getById("credential-$version"))
                assertEquals("legacy-title-$version", passwordRepository.getDecrypted(migrated.id)?.title)
                assertEquals("legacy-password-$version", passwordRepository.getDecrypted(migrated.id)?.password)
                assertTrue(EncryptedField.isContextBound(migrated.title))
                assertTrue(EncryptedField.isContextBound(migrated.encryptedPassword))
                if (version >= 4) {
                    assertEquals(1, passwordRepository.history("credential-$version").size)
                }
            } finally {
                database.close()
                SessionManager.lock()
                context.deleteDatabase(testDb)
            }
        }
    }

    @Test
    fun lockDuringImportRollsBackNewVaultAndPasswords() = runBlocking {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val database = AppDatabase.openForMigrationTest(context, testDb)
        try {
            val vaultRepository = VaultRepository(database.vaultDao())
            val original = vaultRepository.ensureDefault()
            val dao = object : PasswordDao by database.passwordDao() {
                override suspend fun insertAll(items: List<PasswordEntity>) {
                    database.passwordDao().insertAll(items)
                    SessionManager.lock()
                }
            }
            val manager = BackupManager(vaultRepository, PasswordRepository(dao), database)
            assertThrows(VaultLockedException::class.java) {
                runBlocking {
                    manager.importChromeCsv("name,url,username,password\nExample,https://example.com,user,secret", "")
                }
            }
            assertEquals(listOf(original.id), database.vaultDao().getAllVaultsOnce().map { it.id })
            assertTrue(database.passwordDao().getAllIncludingTrashedOnce().isEmpty())
        } finally {
            database.close()
        }
    }

    @Test
    fun closingHistoryCancelsAnInflightPlaintextRead() = runBlocking {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val database = AppDatabase.openForMigrationTest(context, testDb)
        val store = ViewModelStore()
        try {
            val vault = VaultRepository(database.vaultDao()).ensureDefault()
            val repository = PasswordRepository(database.passwordDao())
            val id = repository.save(null, vault.id, "Example", "user", "old-secret", "", emptyList(), "")
            repository.save(id, vault.id, "Example", "user", "new-secret", "", emptyList(), "")
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val finished = CompletableDeferred<Unit>()
            val delayed = object : PasswordDao by database.passwordDao() {
                override suspend fun historyForOnce(passwordId: String) = try {
                    entered.complete(Unit)
                    release.await()
                    database.passwordDao().historyForOnce(passwordId)
                } finally {
                    finished.complete(Unit)
                }
            }
            val viewModel = withContext(Dispatchers.Main) {
                PasswordDetailViewModel(PasswordRepository(delayed)).also {
                    store.put("detail", it)
                    it.load(id)
                    it.loadHistory()
                }
            }
            withTimeout(2_000) { entered.await() }
            withContext(Dispatchers.Main) { viewModel.clearHistory() }
            release.complete(Unit)
            withTimeout(2_000) { finished.await() }
            withContext(Dispatchers.Main) { assertTrue(viewModel.history.value.isEmpty()) }
        } finally {
            withContext(Dispatchers.Main) { store.clear() }
            database.close()
        }
    }

    private fun createHistoricalDatabase(version: Int) {
        context.deleteDatabase(testDb)
        val database = context.openOrCreateDatabase(testDb, Context.MODE_PRIVATE, null)
        try {
            database.execSQL(
                "CREATE TABLE vaults (" +
                    "id TEXT NOT NULL, name TEXT NOT NULL, icon TEXT NOT NULL, " +
                    "createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL, PRIMARY KEY(id))"
            )
            database.execSQL(
                "CREATE TABLE passwords (" +
                    "id TEXT NOT NULL, vaultId TEXT NOT NULL, title TEXT NOT NULL, " +
                    "username TEXT NOT NULL, encryptedPassword TEXT NOT NULL, url TEXT NOT NULL, " +
                    "tags TEXT NOT NULL, encryptedNote TEXT NOT NULL, strengthScore INTEGER NOT NULL, " +
                    "createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL" +
                    (if (version >= 3) ", deletedAt INTEGER NOT NULL DEFAULT 0" else "") +
                    (if (version >= 5) ", favorite INTEGER NOT NULL DEFAULT 0" else "") +
                    ", PRIMARY KEY(id), FOREIGN KEY(vaultId) REFERENCES vaults(id) ON DELETE CASCADE)"
            )
            database.execSQL("CREATE INDEX index_passwords_vaultId ON passwords(vaultId)")
            if (version >= 4) {
                database.execSQL(
                    "CREATE TABLE password_history (" +
                        "id TEXT NOT NULL, passwordId TEXT NOT NULL, encryptedPassword TEXT NOT NULL, " +
                        "changedAt INTEGER NOT NULL, PRIMARY KEY(id), " +
                        "FOREIGN KEY(passwordId) REFERENCES passwords(id) ON DELETE CASCADE)"
                )
                database.execSQL(
                    "CREATE INDEX index_password_history_passwordId ON password_history(passwordId)"
                )
            }
            database.execSQL(
                "INSERT INTO vaults(id, name, icon, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?)",
                arrayOf<Any?>(
                    "vault-$version", legacyMetadata("legacy-vault-$version"), "lock", 1L, 2L
                )
            )
            database.execSQL(
                "INSERT INTO passwords(id, vaultId, title, username, encryptedPassword, url, tags, " +
                    "encryptedNote, strengthScore, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                arrayOf<Any?>(
                    "credential-$version", "vault-$version", legacyMetadata("legacy-title-$version"),
                    legacyMetadata("legacy-user-$version"), legacySecret("legacy-password-$version"),
                    legacyMetadata("https://legacy.example"), legacyMetadata("legacy-tag"),
                    legacySecret("legacy-note"), 10, 1L, 2L
                )
            )
            if (version >= 4) {
                database.execSQL(
                    "INSERT INTO password_history(id, passwordId, encryptedPassword, changedAt) VALUES(?, ?, ?, ?)",
                    arrayOf<Any?>(
                        "history-$version", "credential-$version", legacySecret("old-password"), 2L
                    )
                )
            }
            database.version = version
        } finally {
            database.close()
        }
    }

    private fun legacyMetadata(value: String): String =
        "enc:v1:" + CryptoManager.encryptString(SessionManager.requireKey(), value)

    private fun legacySecret(value: String): String =
        CryptoManager.encryptString(SessionManager.requireKey(), value)
}
