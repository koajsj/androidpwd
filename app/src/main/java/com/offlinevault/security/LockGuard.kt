package com.offlinevault.security

/**
 * Marks a short-lived system UI transition. File pickers must still honour the configured
 * auto-lock timeout on return; only an in-flight biometric prompt may defer that check until its
 * authentication callback resolves.
 */
object LockGuard {
    @Volatile
    var suppressNextBackground: Boolean = false

    @Volatile
    var suppressAutoLockOnReturn: Boolean = false
}
