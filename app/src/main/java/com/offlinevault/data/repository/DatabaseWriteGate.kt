package com.offlinevault.data.repository

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.coroutineContext
import com.offlinevault.security.SessionManager

/** Acquire before Room transactions, never from inside a transaction owned by another writer. */
internal object DatabaseWriteGate {
    private val mutex = Mutex()

    // Room changes dispatchers inside withTransaction. Carry ownership through that handoff so
    // repository calls within the same import do not try to acquire their outer lock again.
    private class Ownership(val generation: Long) : AbstractCoroutineContextElement(Key) {
        companion object Key : CoroutineContext.Key<Ownership>
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
