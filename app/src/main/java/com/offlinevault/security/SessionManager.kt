package com.offlinevault.security

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.SecretKey

/**
 * Holds the in-memory unlocked state of the app. The Data Encryption Key (DEK) only ever lives
 * here while the vault is unlocked. Lock revokes access immediately and erases the key once any
 * already-running operation has unwound, without blocking Android's lifecycle thread.
 */
object SessionManager {

    @Volatile
    private var dek: SecretKey? = null
    private val sessionGenerationCounter = AtomicLong(0)
    private val sessionLock = ReentrantLock()
    private val sessionChanged = sessionLock.newCondition()
    private var activeOperations = 0
    private var changingSession = false

    private val _unlocked = MutableStateFlow(false)
    val unlocked: StateFlow<Boolean> = _unlocked
    private val _activeGeneration = MutableStateFlow<Long?>(null)
    /** Unlike a Boolean, the latest unlock cannot be conflated with an earlier unlocked session. */
    val activeGeneration: StateFlow<Long?> = _activeGeneration

    val isUnlocked: Boolean get() = _unlocked.value
    /** Changes on every lock and unlock, so short-lived authorizations cannot cross sessions. */
    val sessionGeneration: Long get() = sessionGenerationCounter.get()

    fun unlock(key: SecretKey, expectedGeneration: Long = sessionGeneration) {
        sessionLock.lock()
        try {
            if (sessionGeneration != expectedGeneration) {
                throw VaultLockedException("Authentication session expired")
            }
            changingSession = true
            while (activeOperations > 0) sessionChanged.await()
            if (sessionGeneration != expectedGeneration) {
                throw VaultLockedException("Authentication session expired")
            }
            if (dek !== key) CryptoManager.destroyKey(dek)
            dek = key
            val generation = sessionGenerationCounter.incrementAndGet()
            _unlocked.value = true
            _activeGeneration.value = generation
        } finally {
            changingSession = false
            sessionChanged.signalAll()
            sessionLock.unlock()
        }
    }

    fun lock() {
        sessionLock.lock()
        try {
            // Lifecycle callbacks run on Main. Never wait there for a Room suspension which
            // needs Main to resume. Revoke admission/results immediately; retain the old key
            // only until already-running work leaves its gate, then destroy it below.
            changingSession = true
            sessionGenerationCounter.incrementAndGet()
            _unlocked.value = false
            _activeGeneration.value = null
            if (activeOperations == 0) clearLockedKey()
        } finally {
            sessionLock.unlock()
        }
    }

    /** Recovery owns a locked generation, not an unlocked session or a reusable unlock token. */
    internal fun beginRecovery(expectedGeneration: Long): Long {
        sessionLock.lock()
        try {
            if (sessionGeneration != expectedGeneration) throw VaultLockedException("Recovery expired")
            lock()
            return sessionGeneration
        } finally {
            sessionLock.unlock()
        }
    }

    /** Admission only: an edit already admitted may finish after a later lifecycle lock. */
    internal fun withRecoveryCommit(expectedGeneration: Long, block: () -> Unit) {
        sessionLock.lock()
        try {
            if (isUnlocked || sessionGeneration != expectedGeneration) throw VaultLockedException("Recovery expired")
            block()
        } finally {
            sessionLock.unlock()
        }
    }

    /** Returns the active DEK or throws if the app is locked. */
    fun requireKey(): SecretKey {
        if (!isUnlocked) throw VaultLockedException("Vault is locked")
        return dek ?: throw VaultLockedException("Vault is locked")
    }

    /**
     * Captures the current session for a sensitive operation. Call [requireActiveSession] again
     * immediately before committing data so work resumed from an old coroutine cannot write after
     * a lock or a subsequent unlock.
     */
    fun requireActiveSession(): Long {
        requireKey()
        return sessionGenerationCounter.get()
    }

    /**
     * Rejects work that belongs to a session which has since been locked or replaced. Throws
     * [VaultLockedException] (a subtype of [IllegalStateException]) so long-running decrypt loops
     * can distinguish "the vault was locked mid-read" from "this single row is corrupted" and abort
     * the whole read instead of silently dropping rows.
     */
    fun requireActiveSession(expectedGeneration: Long) {
        if (!isUnlocked || dek == null || sessionGenerationCounter.get() != expectedGeneration) {
            throw VaultLockedException("Vault session is no longer active")
        }
    }

    /** Short, non-suspending publication only (UI state / Autofill handoff); never do IO here. */
    fun <T> withActiveSessionNow(expectedGeneration: Long, block: () -> T): T {
        sessionLock.lock()
        try {
            requireActiveSession(expectedGeneration)
            return block().also { requireActiveSession(expectedGeneration) }
        } finally {
            sessionLock.unlock()
        }
    }

    /**
     * Pins key disposal until the operation exits, but never delays revocation. A database
     * transaction must put this gate inside its transaction so invalidation rolls it back.
     */
    suspend fun <T> withActiveSession(block: suspend () -> T): T {
        return withPinnedSession(validateResult = true) { block() }
    }

    /**
     * Credential writes admit their mutation inside DataStore.edit via withActiveSessionNow.
     * An admitted write may finish after lock; do not report that committed write as a failure.
     * This API returns no sensitive result and is not a replacement for guarded reads.
     */
    internal suspend fun withCredentialWrite(block: suspend (Long) -> Unit) {
        withPinnedSession(validateResult = false, block)
    }

    /** The database gate validates inside its transaction, not after a successful commit. */
    internal suspend fun <T> withDatabaseWrite(block: suspend () -> T): T =
        withPinnedSession(validateResult = false) { block() }

    private suspend fun <T> withPinnedSession(validateResult: Boolean, block: suspend (Long) -> T): T {
        val generation: Long
        sessionLock.lock()
        try {
            if (changingSession || !isUnlocked || dek == null) throw VaultLockedException("Vault is locked")
            activeOperations++
            generation = sessionGenerationCounter.get()
        } finally {
            sessionLock.unlock()
        }
        return try {
            block(generation).also { if (validateResult) requireActiveSession(generation) }
        } finally {
            sessionLock.lock()
            try {
                activeOperations--
                if (activeOperations == 0) {
                    if (!isUnlocked) clearLockedKey()
                    sessionChanged.signalAll()
                }
            } finally {
                sessionLock.unlock()
            }
        }
    }

    /** Called only with sessionLock held. */
    private fun clearLockedKey() {
        CryptoManager.destroyKey(dek)
        dek = null
        changingSession = false
        sessionChanged.signalAll()
    }
}

/**
 * Thrown when a sensitive operation runs against a vault that is locked, or whose session was
 * replaced while a long read was in flight. Kept distinct from generic failures so decrypt loops
 * can abort the entire read on a lock instead of misclassifying it as a single corrupted row.
 */
class VaultLockedException(message: String) : IllegalStateException(message)
