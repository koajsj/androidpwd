package com.offlinevault.data.db

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.EncryptedField
import com.offlinevault.security.SessionManager
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
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
