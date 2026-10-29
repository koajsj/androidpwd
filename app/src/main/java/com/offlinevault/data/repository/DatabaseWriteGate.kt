package com.offlinevault.data.repository

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.coroutineContext
import com.offlinevault.security.SessionManager

/** Never treat this as a rolled-back write or automatically replay it. Contains no user data. */
class DatabaseWriteOutcomeException(val committed: Boolean, cause: Throwable? = null) : IllegalStateException(
    if (committed) "操作已提交，请重新解锁后查看结果，不要重复提交"
    else "提交结果未确认，请重新打开列表核对，不要重复提交",
    cause
)

/** Acquire before Room transactions, never from inside a transaction owned by another writer. */
internal object DatabaseWriteGate {
    private val mutex = Mutex()

    // Room changes dispatchers inside withTransaction. Carry ownership through that handoff so
    // repository calls within the same import do not try to acquire their outer lock again.
    private class Ownership(val generation: Long) : AbstractCoroutineContextElement(Key) {
        companion object Key : CoroutineContext.Key<Ownership>
    }

    private class TransactionOwnership : AbstractCoroutineContextElement(Key) {
        companion object Key : CoroutineContext.Key<TransactionOwnership>
    }

    /**
     * [transaction] must return only after commit, or throw and roll back its block. Room provides
     * that contract in production; a completed block without an acknowledged commit is UNKNOWN.
     */
    suspend fun <T> withTransaction(
        transaction: suspend (suspend () -> T) -> T,
        block: suspend () -> T
    ): T {
        var bodyCompleted = false
        var committed = false
        var bodyEntered = false
        var bodyFailure: Exception? = null
        try {
            return withWrite {
                val generation = SessionManager.requireActiveSession()
                if (coroutineContext[TransactionOwnership] != null) {
                    return@withWrite SessionManager.withActiveSession { block() }
                }
                SessionManager.withDatabaseWrite {
                    val result = transaction {
                        withContext(TransactionOwnership()) {
                            bodyEntered = true
                            try {
                                SessionManager.withActiveSession { block() }.also { bodyCompleted = true }
                            } catch (e: Exception) {
                                bodyFailure = e
                                throw e
                            }
                        }
                    }
                    committed = true
                    // Do not release plaintext write results into a later or locked session.
                    if (!SessionManager.isUnlocked || SessionManager.sessionGeneration != generation) {
                        throw DatabaseWriteOutcomeException(committed = true)
                    }
                    result
                }
            }
        } catch (e: DatabaseWriteOutcomeException) {
            throw e
        } catch (e: Exception) {
            if (committed || bodyCompleted ||
                bodyEntered && (e !== bodyFailure || e.suppressed.isNotEmpty())
            ) throw DatabaseWriteOutcomeException(committed, e)
            throw e
        }
    }

    suspend fun <T> withWrite(block: suspend () -> T): T {
        val ownership = coroutineContext[Ownership]
        val generation = ownership?.generation ?: SessionManager.requireActiveSession()
        if (ownership != null) {
            SessionManager.requireActiveSession(generation)
            return block()
        }
        return mutex.withLock {
            // A writer queued in session A must not gain permission from a later session B.
            SessionManager.requireActiveSession(generation)
            withContext(Ownership(generation)) { block() }
        }
    }
}
