package com.offlinevault.data.repository

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.Before
import org.junit.After
import org.junit.Assert.assertTrue
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.SessionManager
import com.offlinevault.security.VaultLockedException
import org.junit.Assert.assertThrows
import kotlinx.coroutines.CancellationException

class DatabaseWriteGateTest {
    @Before fun unlock() { SessionManager.unlock(CryptoManager.newDataEncryptionKey()) }
    @After fun lock() { SessionManager.lock() }

    @Test fun nullableResultDoesNotExecuteTheWriteTwice() = runBlocking {
        var attempts = 0
        val result: String? = DatabaseWriteGate.withTransaction(transaction = { action -> action() }) {
            attempts++
            null
        }
        assertEquals(null, result)
        assertEquals(1, attempts)
    }

    @Test fun rollbackFailureCannotBeReportedAsDefinitelyRolledBack() = runBlocking {
        val outcome = assertThrows(DatabaseWriteOutcomeException::class.java) {
            runBlocking {
                DatabaseWriteGate.withTransaction(transaction = { action ->
                    try { action() } catch (_: Exception) { error("Synthetic rollback IO failure") }
                }) { throw IllegalArgumentException("Synthetic body failure") }
            }
        }
        assertFalse(outcome.committed)
    }

    @Test fun committedWriteIsNotReportedAsRolledBackWhenLockFollowsCommit() = runBlocking {
        var persisted = 0
        val outcome = assertThrows(DatabaseWriteOutcomeException::class.java) {
            runBlocking {
                DatabaseWriteGate.withTransaction(
                    transaction = { action -> action().also { SessionManager.lock() } }
                ) { persisted++; "not publishable after lock" }
            }
        }
        assertTrue(outcome.committed)
        assertEquals(1, persisted)
    }

    @Test fun lockInsideTransactionRollsBackBeforeCommitValidation() = runBlocking {
        var persisted = 0
        assertThrows(VaultLockedException::class.java) {
            runBlocking {
                DatabaseWriteGate.withTransaction(
                    transaction = { action ->
                        val before = persisted
                        try { action() } catch (e: Exception) { persisted = before; throw e }
                    }
                ) { persisted++; SessionManager.lock() }
            }
        }
        assertEquals(0, persisted)
    }

    @Test fun exceptionInsideTransactionIsNotMislabelledAsAnUnknownCommit() = runBlocking {
        val failure = IllegalArgumentException("synthetic constraint failure")
        val caught = runCatching {
            DatabaseWriteGate.withTransaction(transaction = { action -> action() }) { throw failure }
        }.exceptionOrNull()
        assertTrue(caught === failure)
    }

    @Test fun cancellationAfterCompletedBodyHasAnExplicitUnknownOutcome() = runBlocking {
        val outcome = assertThrows(DatabaseWriteOutcomeException::class.java) {
            runBlocking {
                DatabaseWriteGate.withTransaction(
                    transaction = { action -> action(); throw CancellationException("No commit acknowledgement") }
                ) { 42 }
            }
        }
        assertFalse(outcome.committed)
        assertTrue(outcome.cause is CancellationException)
    }

    @Test fun nestedRepositoryCallsUseOneCommitAndNoIndependentReceipt() = runBlocking {
        var commits = 0
        val result = DatabaseWriteGate.withTransaction(transaction = { action -> action().also { commits++ } }) {
            DatabaseWriteGate.withTransaction(transaction = { error("Must reuse outer transaction") }) { 42 }
        }
        assertEquals(42, result)
        assertEquals(1, commits)
    }

    @Test fun unknownOutcomeIsNotAutomaticallyRetried() = runBlocking {
        var attempts = 0
        runCatching {
            DatabaseWriteGate.withTransaction(transaction = { action -> action(); error("Commit IO failed") }) {
                attempts++
            }
        }.onFailure { assertTrue(it is DatabaseWriteOutcomeException) }
        assertEquals(1, attempts)
    }

    @Test fun queuedWriterCannotBorrowANewSession() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val first = async {
            DatabaseWriteGate.withWrite { entered.complete(Unit); release.await() }
        }
        entered.await()
        var wrote = false
        val attempted = CompletableDeferred<Unit>()
        val second = async {
            attempted.complete(Unit)
            runCatching { DatabaseWriteGate.withWrite { wrote = true } }
        }
        attempted.await()
        SessionManager.lock()
        SessionManager.unlock(CryptoManager.newDataEncryptionKey())
        release.complete(Unit)
        first.await()
        assertTrue(second.await().exceptionOrNull() is VaultLockedException)
        assertFalse(wrote)
    }
    @Test fun nestedRepositoryWritesSurviveTransactionDispatcherHandoff() = runBlocking {
        val result = withTimeout(2_000) {
            DatabaseWriteGate.withWrite {
                withContext(Dispatchers.IO) {
                    DatabaseWriteGate.withWrite { 42 }
                }
            }
        }
        assertEquals(42, result)
    }

    @Test fun unrelatedWritersWaitBeforeEnteringTheirRoomTransaction() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val first = async(Dispatchers.Default) {
            DatabaseWriteGate.withWrite {
                entered.complete(Unit)
                release.await()
            }
        }
        entered.await()
        val attempted = CompletableDeferred<Unit>()
        val second = async(Dispatchers.Default) {
            attempted.complete(Unit)
            DatabaseWriteGate.withWrite { "transaction" }
        }
        try {
            attempted.await()
            assertFalse(second.isCompleted)
        } finally {
            release.complete(Unit)
        }
        withTimeout(2_000) {
            first.await()
            assertEquals("transaction", second.await())
        }
    }

    @Test fun cancelledWriterReleasesTheGate() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        val first = async(Dispatchers.Default) {
            DatabaseWriteGate.withWrite {
                entered.complete(Unit)
                CompletableDeferred<Unit>().await()
            }
        }
        entered.await()
        first.cancel()
        first.join()
        assertEquals(42, withTimeout(2_000) { DatabaseWriteGate.withWrite { 42 } })
    }
}
