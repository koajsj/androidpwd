package com.offlinevault.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskEngineTest {

    @Test
    fun normalContext_allowsBiometricOnly() {
        val score = evaluate(RiskContext(false, false, 0, 1, 1_000L, 14, 2_000L))

        assertEquals(0, score.score)
        assertEquals(RiskLevel.LOW, score.level)
        assertTrue(score.allowsBiometricOnly)
    }

    @Test
    fun untrustedDevice_requiresEnhancedAuthentication() {
        val score = evaluate(RiskContext(true, false, 0, 1, 1_000L, 14, 2_000L))

        assertEquals(45, score.score)
        assertEquals(RiskLevel.MEDIUM, score.level)
        assertTrue(score.allowsBiometricOnly)
    }

    @Test
    fun rootedDevice_requiresMasterCredentialInsteadOfBiometricOnly() {
        val score = evaluate(RiskContext(false, true, 0, 1, 1_000L, 14, 2_000L))

        assertEquals(RiskLevel.HIGH, score.level)
        assertFalse(score.allowsBiometricOnly)
    }

    @Test
    fun repeatedFailuresAndNightAccess_raiseRisk() {
        val score = evaluate(RiskContext(false, false, 6, 1, 1_000L, 2, 2_000L))

        assertEquals(40, score.score)
        assertEquals(RiskLevel.MEDIUM, score.level)
        assertTrue(score.reasons.any { it.contains("解锁失败") })
    }

    @Test
    fun riskLevelBoundaries_areExactAndScoresAreClamped() {
        assertEquals(RiskLevel.LOW, evaluatePoints(39).level)
        assertEquals(RiskLevel.MEDIUM, evaluatePoints(40).level)
        assertEquals(RiskLevel.MEDIUM, evaluatePoints(69).level)
        assertEquals(RiskLevel.HIGH, evaluatePoints(70).level)
        assertEquals(100, evaluatePoints(150).score)
        assertEquals(0, evaluatePoints(-20).score)
    }

    @Test
    fun futureAccessWindowDoesNotCountAsHighFrequencyAccess() {
        val score = evaluate(
            RiskContext(
                isNewDeviceState = false,
                isRooted = false,
                failedAttempts = 0,
                successfulUnlocksInWindow = 8,
                unlockWindowStartedAt = 10_000L,
                hourOfDay = 14,
                nowMillis = 9_000L
            )
        )

        assertEquals(0, score.score)
        assertEquals(RiskLevel.LOW, score.level)
    }

    private fun evaluate(context: RiskContext): RiskScore = RiskPolicyEvaluator.evaluate(
        context,
        listOf(DeviceRiskRule(), BehaviorRiskRule(), TimeRiskRule())
    )

    private fun evaluatePoints(points: Int): RiskScore = RiskPolicyEvaluator.evaluate(
        RiskContext(false, false, 0, 0, 0L, 12, 1_000L),
        listOf(RiskRule { RiskRuleResult(points) })
    )
}
