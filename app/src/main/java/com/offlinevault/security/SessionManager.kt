package com.offlinevault.security

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.SecretKey

/**
 * Holds the in-memory unlocked state of the app. The Data Encryption Key (DEK) only ever lives
 * here while the vault is unlocked, and is dropped the moment the app is locked or backgrounded.
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

    val isUnlocked: Boolean get() = dek != null
    /** Changes on every lock and unlock, so short-lived authorizations cannot cross sessions. */
    val sessionGeneration: Long get() = sessionGenerationCounter.get()

    fun unlock(key: SecretKey) {
        awaitSessionOperations()
        try {
            if (dek !== key) CryptoManager.destroyKey(dek)
            dek = key
            sessionGenerationCounter.incrementAndGet()
            _unlocked.value = true
        } finally {
            finishSessionChange()
        }
    }

    fun lock() {
        awaitSessionOperations()
        try {
            CryptoManager.destroyKey(dek)
            dek = null
            sessionGenerationCounter.incrementAndGet()
            _unlocked.value = false
        } finally {
            finishSessionChange()
        }
    }

    /** Returns the active DEK or throws if the app is locked. */
    fun requireKey(): SecretKey =
        dek ?: throw VaultLockedException("Vault is locked")

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
        if (dek == null || sessionGenerationCounter.get() != expectedGeneration) {
            throw VaultLockedException("Vault session is no longer active")
        }
    }

    /**
     * Runs a sensitive operation while lock/unlock is excluded from its database commit.
     * The generation is verified before a result escapes, so old-session data cannot be
     * published if session-transition behavior changes in the future.
     */
    suspend fun <T> withActiveSession(block: suspend () -> T): T {
        val generation: Long
        sessionLock.lock()
        try {
            if (changingSession || dek == null) throw VaultLockedException("Vault is locked")
            activeOperations++
            generation = sessionGenerationCounter.get()
        } finally {
            sessionLock.unlock()
        }
        return try {
            block().also { requireActiveSession(generation) }
        } finally {
            sessionLock.lock()
            try {
                activeOperations--
                if (activeOperations == 0) sessionChanged.signalAll()
            } finally {
                sessionLock.unlock()
            }
        }
    }

    private fun awaitSessionOperations() {
        sessionLock.lock()
        try {
            changingSession = true
            while (activeOperations > 0) sessionChanged.await()
        } finally {
            sessionLock.unlock()
        }
    }

    private fun finishSessionChange() {
        sessionLock.lock()
        try {
            changingSession = false
            sessionChanged.signalAll()
        } finally {
            sessionLock.unlock()
        }
    }
}

/**
 * Thrown when a sensitive operation runs against a vault that is locked, or whose session was
 * replaced while a long read was in flight. Kept distinct from generic failures so decrypt loops
 * can abort the entire read on a lock instead of misclassifying it as a single corrupted row.
 */
class VaultLockedException(message: String) : IllegalStateException(message)
