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

class DatabaseWriteGateTest {
    @Before fun unlock() { SessionManager.unlock(CryptoManager.newDataEncryptionKey()) }
    @After fun lock() { SessionManager.lock() }

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
