package com.offlinevault.security

import org.junit.After
import org.junit.Before
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedFieldTest {

    @Before
    fun unlock() {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
    }

    @After
    fun lock() {
        SessionManager.lock()
    }

    @Test
    fun currentFieldsAreBoundToContextAndLiteralPrefixesRemainPlaintext() {
        val encrypted = EncryptedField.encrypt("enc:v1:literal-title", "credential:1:title")
        assertEquals(
            "enc:v1:literal-title",
            EncryptedField.decrypt(encrypted, "credential:1:title")
        )
        assertThrows(Exception::class.java) {
            EncryptedField.decrypt(encrypted, "credential:2:title")
        }
    }

    @Test
    fun legacyFieldMigratesToContextBoundFormat() {
        val legacy = "enc:v1:" + CryptoManager.encryptString(SessionManager.requireKey(), "旧标题")
        val migrated = EncryptedField.migrate(legacy, "credential:1:title")
        assertEquals("旧标题", EncryptedField.decrypt(migrated, "credential:1:title"))
    }

    @Test
    fun plaintextMetadataIsOnlyReadableThroughMigration() {
        val legacyPlaintext = "旧标题"
        assertTrue(EncryptedField.requiresMetadataMigration(legacyPlaintext))
        assertThrows(VaultDataCorruptionException::class.java) {
            EncryptedField.decrypt(legacyPlaintext, "credential:1:title")
        }
        val migrated = EncryptedField.migrate(legacyPlaintext, "credential:1:title")
        assertEquals("旧标题", EncryptedField.decrypt(migrated, "credential:1:title"))
    }

    @Test
    fun historySecretsAreBoundToTheirOwnHistoryRecord() {
        val encrypted = EncryptedField.encryptHistorySecret(
            "previous-password",
            credentialId = "credential-1",
            historyId = "history-1"
        )
        assertEquals(
            "previous-password",
            EncryptedField.decryptHistorySecret(encrypted, "credential-1", "history-1")
        )
        assertThrows(Exception::class.java) {
            EncryptedField.decryptHistorySecret(encrypted, "credential-1", "history-2")
        }
    }

    @Test
    fun legacyHistoryEnvelopeMigratesWithoutChangingItsPassword() {
        // Released history rows copied the live credential-password envelope.
        val legacy = EncryptedField.encryptSecret("old-password", "credential:1:password")
        val migrated = EncryptedField.migrateHistorySecret(
            legacy,
            credentialId = "1",
            historyId = "history-1"
        )
        assertTrue(migrated.startsWith("enc:v3:"))
        assertEquals(
            "old-password",
            EncryptedField.decryptHistorySecret(migrated, "1", "history-1")
        )
    }
}
