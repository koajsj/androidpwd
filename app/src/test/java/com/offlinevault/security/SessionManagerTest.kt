package com.offlinevault.security

import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Test

class SessionManagerTest {

    @After
    fun tearDown() {
        SessionManager.lock()
    }

    @Test
    fun capturedWriteSessionCannotCrossLockOrNewUnlock() {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val originalGeneration = SessionManager.requireActiveSession()

        SessionManager.lock()
        assertThrows(IllegalStateException::class.java) {
            SessionManager.requireActiveSession(originalGeneration)
        }

        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        assertThrows(IllegalStateException::class.java) {
            SessionManager.requireActiveSession(originalGeneration)
        }
    }
}
