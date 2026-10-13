package com.offlinevault.security

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertFalse
import org.junit.Test
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
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
    fun anAuthenticationStartedBeforeLockCannotReopenTheSession() {
        val generation = SessionManager.sessionGeneration
        SessionManager.lock()
        val key = CryptoManager.newDataEncryptionKey()
        try {
            assertThrows(VaultLockedException::class.java) {
                SessionManager.unlock(key, generation)
            }
            assertFalse(SessionManager.isUnlocked)
        } finally {
            CryptoManager.destroyKey(key)
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
    fun synchronousPublicationCannotUseAnOldSessionGeneration() {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val generation = SessionManager.requireActiveSession()
        assertEquals(42, SessionManager.withActiveSessionNow(generation) { 42 })
        SessionManager.lock()
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        assertThrows(VaultLockedException::class.java) {
            SessionManager.withActiveSessionNow(generation) { error("Must not publish") }
        }
    }

    @Test
    fun lockImmediatelyInvalidatesSuspendedOperationsWithoutBlockingItsCaller() = runBlocking {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val operation = async(Dispatchers.Default) {
            try {
                SessionManager.withActiveSession {
                    entered.complete(Unit)
                    release.await()
                }
                false
            } catch (_: VaultLockedException) {
                true
            }
        }
        entered.await()

        val locking = async(Dispatchers.Default) { SessionManager.lock() }
        try {
            withTimeout(1_000) { locking.await() }
            assertFalse(SessionManager.isUnlocked)
            assertThrows(VaultLockedException::class.java) { SessionManager.requireKey() }
        } finally {
            release.complete(Unit)
            withTimeout(1_000) { locking.await() }
        }
        assertEquals(true, withTimeout(1_000) { operation.await() })
        assertEquals(false, SessionManager.isUnlocked)
    }
}
