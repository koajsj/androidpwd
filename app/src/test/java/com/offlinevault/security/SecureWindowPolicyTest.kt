package com.offlinevault.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureWindowPolicyTest {
    @Test fun forcedProtectionSurvivesPreferenceChangesAndNestedOwners() {
        val policy = SecureWindowPolicy()
        assertTrue(policy.isSecure)
        policy.screenshotBlocked = false
        assertFalse(policy.isSecure)
        policy.acquire()
        policy.acquire()
        policy.screenshotBlocked = false // preference re-emitted on return to foreground
        assertTrue(policy.isSecure)
        policy.release()
        assertTrue(policy.isSecure)
        policy.release()
        assertFalse(policy.isSecure)
    }

    @Test fun leavingSensitivePageKeepsTheCurrentPreferenceInsteadOfAnOldSnapshot() {
        val policy = SecureWindowPolicy()
        policy.screenshotBlocked = false
        policy.acquire()
        policy.screenshotBlocked = true
        policy.release()
        assertTrue(policy.isSecure)
    }
}
