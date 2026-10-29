package com.offlinevault.data.db

import androidx.room.testing.MigrationTestHelper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.EncryptedField
import com.offlinevault.security.SessionManager
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*
import kotlinx.coroutines.runBlocking
import com.offlinevault.data.dao.PasswordDao
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.security.VaultLockedException

@RunWith(AndroidJUnit4::class)
class CustomFieldsMigrationTest {
    @get:Rule val helper = MigrationTestHelper(InstrumentationRegistry.getInstrumentation(), AppDatabase::class.java)

    @Test fun v5ToV6PreservesCiphertextAndAddsOnlyAnEmptyPayload() {
        val name = "custom-fields-migration-test.db"
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val encrypted = EncryptedField.encryptSecret("synthetic-original", "credential:test:password")
        try {
            helper.createDatabase(name, 5).use { db ->
                db.execSQL("INSERT INTO vaults VALUES ('vault','synthetic','lock',1,1)")
                db.execSQL("INSERT INTO passwords (id,vaultId,title,username,encryptedPassword,url,tags,encryptedNote,strengthScore,createdAt,updatedAt,deletedAt,favorite) VALUES ('test','vault','','',?,'','','',50,1,1,0,0)", arrayOf(encrypted))
            }
            helper.runMigrationsAndValidate(name, 6, true, AppDatabase.MIGRATION_5_6).use { db ->
                db.query("SELECT encryptedPassword,encryptedCustomFields FROM passwords WHERE id='test'").use { c ->
                    assertTrue(c.moveToFirst())
                    assertEquals(encrypted, c.getString(0))
                    assertEquals("", c.getString(1))
                    assertEquals("synthetic-original", EncryptedField.decryptSecret(c.getString(0), "credential:test:password"))
                }
                assertTrue(db.isDatabaseIntegrityOk)
            }
        } finally {
            SessionManager.lock()
            InstrumentationRegistry.getInstrumentation().targetContext.deleteDatabase(name)
        }
    }

    @Test fun lockBeforeBatchCommitRollsBackAllUpdates() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val name = "custom-field-batch-rollback.db"
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val database = AppDatabase.openForMigrationTest(context, name)
        try {
            val vault = VaultRepository(database.vaultDao()).ensureDefault()
            val repo = PasswordRepository(database.passwordDao(), database)
            val id = repo.save(null, vault.id, "Synthetic", "u", "synthetic", "", emptyList(), "")
            val dao = object : PasswordDao by database.passwordDao() {
                override suspend fun updateBatch(items: List<PasswordEntity>) {
                    database.passwordDao().updateBatch(items)
                    SessionManager.lock()
                }
            }
            assertThrows(VaultLockedException::class.java) { runBlocking {
                PasswordRepository(dao, database).updateMany(vault.id, setOf(id), favorite = true)
            } }
            assertFalse(requireNotNull(database.passwordDao().getById(id)).favorite)
        } finally {
            database.close()
            SessionManager.lock()
            context.deleteDatabase(name)
        }
    }
}
