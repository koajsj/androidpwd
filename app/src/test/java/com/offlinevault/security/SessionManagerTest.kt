package com.offlinevault.security

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

class SessionManagerTest {

    @Test
    fun recoveryCommitCannotCrossALockOrANewSession() {
        val generation = SessionManager.beginRecovery(SessionManager.sessionGeneration)
        var committed = false
        SessionManager.withRecoveryCommit(generation) { committed = true }
        assertTrue(committed)
        SessionManager.lock()
        assertThrows(VaultLockedException::class.java) {
            SessionManager.withRecoveryCommit(generation) { error("Stale recovery must not commit") }
        }
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        assertThrows(VaultLockedException::class.java) {
            SessionManager.beginRecovery(generation)
        }
        assertTrue(SessionManager.isUnlocked)
    }

    @Test
    fun aSlowObserverStillSeesTheLatestUnlockGeneration() = runBlocking {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val first = SessionManager.requireActiveSession()
        val entered = CompletableDeferred<Unit>()
        val resume = CompletableDeferred<Unit>()
        val observed = CompletableDeferred<Long>()
        val observer = launch(start = CoroutineStart.UNDISPATCHED) {
            SessionManager.activeGeneration.collect { generation ->
                if (generation == first) {
                    entered.complete(Unit)
                    resume.await()
                } else if (generation != null) {
                    observed.complete(generation)
                }
            }
        }
        try {
            entered.await()
            SessionManager.lock()
            assertEquals(null, SessionManager.activeGeneration.value)
            SessionManager.unlock(CryptoManager.newDataEncryptionKey())
            val latest = SessionManager.requireActiveSession()
            resume.complete(Unit)
            assertEquals(latest, withTimeout(1_000) { observed.await() })
        } finally {
            observer.cancel()
        }
    }

    @After
    fun tearDown() {
        SessionManager.lock()
    }

    @Test
    fun admittedCredentialWriteCanFinishAfterLockWithoutReportingAFalseFailure() = runBlocking {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        val admitted = CompletableDeferred<Unit>()
        val finishPersistence = CompletableDeferred<Unit>()
        val write = async(start = CoroutineStart.UNDISPATCHED) {
            SessionManager.withCredentialWrite { generation ->
                SessionManager.withActiveSessionNow(generation) { admitted.complete(Unit) }
                finishPersistence.await()
            }
        }
        admitted.await()
        SessionManager.lock()
        assertFalse(SessionManager.isUnlocked)
        finishPersistence.complete(Unit)
        withTimeout(1_000) { write.await() }
        assertThrows(VaultLockedException::class.java) { SessionManager.requireKey() }
        Unit
    }

    @Test
    fun credentialWriteLockedBeforeAdmissionCannotMutateState() = runBlocking {
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        var mutated = false
        assertThrows(VaultLockedException::class.java) {
            runBlocking {
                SessionManager.withCredentialWrite { generation ->
                    SessionManager.lock()
                    SessionManager.withActiveSessionNow(generation) { mutated = true }
                }
            }
        }
        assertFalse(mutated)
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
