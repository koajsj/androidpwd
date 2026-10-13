package com.offlinevault.data.repository

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.coroutineContext

/** Acquire before Room transactions, never from inside a transaction owned by another writer. */
internal object DatabaseWriteGate {
    private val mutex = Mutex()

    // Room changes dispatchers inside withTransaction. Carry ownership through that handoff so
    // repository calls within the same import do not try to acquire their outer lock again.
    private class Ownership : AbstractCoroutineContextElement(Key) {
        companion object Key : CoroutineContext.Key<Ownership>
    }

    suspend fun <T> withWrite(block: suspend () -> T): T {
        if (coroutineContext[Ownership] != null) return block()
        return mutex.withLock { withContext(Ownership()) { block() } }
    }
}
