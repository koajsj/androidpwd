package com.offlinevault.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedFieldTest {

    @Test
    fun currentFieldsAreBoundToContextAndLiteralPrefixesRemainPlaintext() {
        val key = CryptoManager.newDataEncryptionKey()
        SessionManager.unlock(key)
        try {
            val encrypted = EncryptedField.encrypt("enc:v1:literal-title", "credential:1:title")
            assertEquals(
                "enc:v1:literal-title",
                EncryptedField.decrypt(encrypted, "credential:1:title")
            )
            assertThrows(Exception::class.java) {
                EncryptedField.decrypt(encrypted, "credential:2:title")
            }
        } finally {
            SessionManager.lock()
        }
    }

    @Test
    fun legacyFieldMigratesToContextBoundFormat() {
        val key = CryptoManager.newDataEncryptionKey()
        SessionManager.unlock(key)
        try {
            val legacy = "enc:v1:" + CryptoManager.encryptString(SessionManager.requireKey(), "旧标题")
            val migrated = EncryptedField.migrate(legacy, "credential:1:title")
            assertEquals("旧标题", EncryptedField.decrypt(migrated, "credential:1:title"))
        } finally {
            SessionManager.lock()
        }
    }

    @Test
    fun plaintextMetadataIsOnlyReadableThroughMigration() {
        val key = CryptoManager.newDataEncryptionKey()
        SessionManager.unlock(key)
        try {
            val legacyPlaintext = "旧标题"
            assertTrue(EncryptedField.requiresMetadataMigration(legacyPlaintext))
            assertThrows(VaultDataCorruptionException::class.java) {
                EncryptedField.decrypt(legacyPlaintext, "credential:1:title")
            }
            val migrated = EncryptedField.migrate(legacyPlaintext, "credential:1:title")
            assertEquals("旧标题", EncryptedField.decrypt(migrated, "credential:1:title"))
        } finally {
            SessionManager.lock()
        }
    }
}
