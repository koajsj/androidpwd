package com.offlinevault.security

/** Main-thread policy: a sensitive page overrides the user's general screenshot preference. */
internal class SecureWindowPolicy {
    var screenshotBlocked: Boolean = true
    private var sensitiveOwners = 0
    val isSecure: Boolean get() = screenshotBlocked || sensitiveOwners > 0

    fun acquire() { sensitiveOwners++ }
    fun release() {
        check(sensitiveOwners > 0)
        sensitiveOwners--
    }
}
