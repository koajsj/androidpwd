package com.offlinevault.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordSecurityAnalyzerTest {

    private val now = 1_800_000_000_000L

    @Test
    fun healthyUniqueCredentials_receiveFullScore() {
        val report = PasswordSecurityAnalyzer.analyze(
            listOf(
                candidate("one", "first"),
                candidate("two", "second")
            ),
            now
        )

        assertEquals(100, report.score)
        assertEquals(SecurityLevel.LOW, report.level)
        assertTrue(report.risks.isEmpty())
    }

    @Test
    fun weakReusedAndStaleCredentials_areReportedWithoutPasswordMaterial() {
        val old = now - 366L * 24 * 60 * 60 * 1_000L
        val report = PasswordSecurityAnalyzer.analyze(
            listOf(
                PasswordSecurityCandidate("one", 5, "same", 6, 1, true, old),
                PasswordSecurityCandidate("two", 5, "same", 6, 1, true, old)
            ),
            now
        )

        assertEquals(SecurityLevel.CRITICAL, report.level)
        assertEquals(setOf("one", "two"), report.weakCredentialIds)
        assertEquals(setOf("one", "two"), report.reusedCredentialIds)
        assertEquals(setOf("one", "two"), report.staleCredentialIds)
        assertEquals(2, report.risks.size)
    }

    @Test fun ageAloneDoesNotReduceScoreOrCreateARisk() {
        val fresh = candidate("one", "unique")
        val old = fresh.copy(updatedAt = now - 1000L * 24 * 60 * 60 * 1000)
        val current = PasswordSecurityAnalyzer.analyze(listOf(fresh), now)
        val historical = PasswordSecurityAnalyzer.analyze(listOf(old), now)
        assertEquals(current.score, historical.score)
        assertTrue(historical.risks.isEmpty())
        assertEquals(setOf("one"), historical.staleCredentialIds)
    }

    @Test
    fun emptyPassword_isNeverTreatedAsUniqueOrHealthy() {
        val report = PasswordSecurityAnalyzer.analyze(
            listOf(
                PasswordSecurityCandidate("empty", 0, null, 0, 0, false, now)
            ),
            now
        )

        assertEquals(setOf("empty"), report.weakCredentialIds)
        assertTrue(report.score < 40)
    }

    private fun candidate(id: String, fingerprint: String) = PasswordSecurityCandidate(
        id = id,
        strengthScore = 90,
        passwordFingerprint = fingerprint,
        passwordLength = 16,
        characterClasses = 4,
        isCommonWeakPassword = false,
        updatedAt = now
    )
}
