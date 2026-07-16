package com.offlinevault.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CryptoManagerTest {
    @Test fun acceptsSupportedPbkdf2IterationCounts() {
        assertEquals(
            CryptoManager.DEFAULT_PBKDF2_ITERATIONS,
            CryptoManager.requireValidIterations(CryptoManager.DEFAULT_PBKDF2_ITERATIONS)
        )
        assertEquals(
            CryptoManager.LEGACY_PBKDF2_ITERATIONS,
            CryptoManager.requireValidIterations(CryptoManager.LEGACY_PBKDF2_ITERATIONS)
        )
    }

    @Test fun rejectsUnboundedPbkdf2IterationCounts() {
        assertThrows(IllegalArgumentException::class.java) {
            CryptoManager.requireValidIterations(Int.MAX_VALUE)
        }
        assertThrows(IllegalArgumentException::class.java) {
            CryptoManager.requireValidIterations(1)
        }
    }

    @Test fun legacyAndCurrentKdfVersionsResolveToPbkdf2() {
        assertEquals(
            KdfVersions.PBKDF2_HMAC_SHA256_V1,
            KdfVersions.stored(null, CryptoManager.LEGACY_PBKDF2_ITERATIONS).version
        )
        assertEquals(
            KdfVersions.PBKDF2_HMAC_SHA256_V1,
            KdfVersions.current().version
        )
    }

    @Test fun rejectsReservedKdfUntilItsImplementationExists() {
        assertThrows(IllegalArgumentException::class.java) {
            KdfVersions.stored(KdfVersions.ARGON2ID_V1, CryptoManager.DEFAULT_PBKDF2_ITERATIONS)
        }
    }
}
