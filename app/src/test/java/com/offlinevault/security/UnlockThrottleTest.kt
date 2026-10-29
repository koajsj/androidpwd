package com.offlinevault.security

import org.junit.Assert.assertEquals
import org.junit.Test

class UnlockThrottleTest {
    @Test fun delayStartsAtThirdFailureAndDoubles() {
        assertEquals(0, UnlockThrottle.remainingSeconds(2, 1_000, 1_000))
        assertEquals(5, UnlockThrottle.remainingSeconds(3, 10_000, 10_000))
        assertEquals(10, UnlockThrottle.remainingSeconds(4, 10_000, 10_000))
        assertEquals(20, UnlockThrottle.remainingSeconds(5, 10_000, 10_000))
    }

    @Test fun delayExpiresAndCapsAtFiveMinutes() {
        assertEquals(0, UnlockThrottle.remainingSeconds(3, 10_000, 15_000))
        assertEquals(300, UnlockThrottle.remainingSeconds(100, 10_000, 10_000))
    }

    @Test fun movingClockBackDoesNotBypassDelay() {
        assertEquals(5, UnlockThrottle.remainingSeconds(3, 10_000, 1_000))
    }
}
