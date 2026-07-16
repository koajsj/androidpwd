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
        dek = key
        sessionGenerationCounter.incrementAndGet()
        _unlocked.value = true
    }

    @Synchronized
    fun lock() {
        dek = null
        sessionGenerationCounter.incrementAndGet()
        _unlocked.value = false
    }

    /** Returns the active DEK or throws if the app is locked. */
    fun requireKey(): SecretKey =
        dek ?: throw IllegalStateException("Vault is locked")
}
