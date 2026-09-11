package com.offlinevault.security

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

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

    @Test
    fun activeSessionGateRunsOnlyWhileUnlocked() = runBlocking {
        assertThrows(IllegalStateException::class.java) {
            runBlocking { SessionManager.withActiveSession { Unit } }
        }

        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val result = SessionManager.withActiveSession { 42 }
        assertEquals(42, result)
    }

    @Test
    fun activeSessionGenerationRejectsAResultAfterLock() = runBlocking {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val generation = SessionManager.requireActiveSession()
        assertEquals("decrypted", SessionManager.withActiveSession {
            SessionManager.requireActiveSession(generation)
            "decrypted"
        })
        SessionManager.lock()
        assertThrows(IllegalStateException::class.java) {
            SessionManager.requireActiveSession(generation)
        }
        Unit
    }

    @Test
    fun lockWaitsForAnActiveSensitiveOperationToFinish() = runBlocking {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val operation = async(Dispatchers.Default) {
            SessionManager.withActiveSession {
                entered.complete(Unit)
                release.await()
            }
        }
        entered.await()

        val locking = async(Dispatchers.Default) { SessionManager.lock() }
        delay(50)
        assertEquals(false, locking.isCompleted)

        release.complete(Unit)
        withTimeout(1_000) {
            operation.await()
            locking.await()
        }
        assertEquals(false, SessionManager.isUnlocked)
    }
}
