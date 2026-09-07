package com.offlinevault.security

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.SecretKey

/**
 * Holds the in-memory unlocked state of the app. The Data Encryption Key (DEK) only ever lives
 * here while the vault is unlocked, and is dropped the moment the app is locked or backgrounded.
 */
object SessionManager {

    @Volatile
    private var dek: SecretKey? = null
    private val sessionGenerationCounter = AtomicLong(0)

    private val _unlocked = MutableStateFlow(false)
    val unlocked: StateFlow<Boolean> = _unlocked

    val isUnlocked: Boolean get() = dek != null
    /** Changes on every lock and unlock, so short-lived authorizations cannot cross sessions. */
    val sessionGeneration: Long get() = sessionGenerationCounter.get()

    @Synchronized
    fun unlock(key: SecretKey) {
        if (dek !== key) CryptoManager.destroyKey(dek)
        dek = key
        sessionGenerationCounter.incrementAndGet()
        _unlocked.value = true
    }

    @Synchronized
    fun lock() {
        CryptoManager.destroyKey(dek)
        dek = null
        sessionGenerationCounter.incrementAndGet()
        _unlocked.value = false
    }

    /** Returns the active DEK or throws if the app is locked. */
    fun requireKey(): SecretKey =
        dek ?: throw IllegalStateException("Vault is locked")

    /**
     * Captures the current session for a sensitive operation. Call [requireActiveSession] again
     * immediately before committing data so work resumed from an old coroutine cannot write after
     * a lock or a subsequent unlock.
     */
    @Synchronized
    fun requireActiveSession(): Long {
        requireKey()
        return sessionGenerationCounter.get()
    }

    /** Rejects work that belongs to a session which has since been locked or replaced. */
    @Synchronized
    fun requireActiveSession(expectedGeneration: Long) {
        check(dek != null && sessionGenerationCounter.get() == expectedGeneration) {
            "Vault session is no longer active"
        }
    }
}
