package com.offlinevault.security

import android.os.Build
import com.offlinevault.data.preferences.SecurityPreferences
import java.io.File

enum class RiskLevel { LOW, MEDIUM, HIGH }

data class RiskScore(
    val score: Int,
    val level: RiskLevel,
    val reasons: List<String>
) {
    init {
        require(score in 0..100) { "Risk score must be between 0 and 100" }
    }

    /** High-risk sessions require the configured master credential; biometric alone is not enough. */
    val allowsBiometricOnly: Boolean get() = level != RiskLevel.HIGH
}

data class RiskContext(
    val isNewDeviceState: Boolean,
    val isRooted: Boolean,
    val failedAttempts: Int,
    val successfulUnlocksInWindow: Int,
    val unlockWindowStartedAt: Long,
    val hourOfDay: Int,
    val nowMillis: Long
)

data class RiskRuleResult(val points: Int, val reason: String? = null)

fun interface RiskRule {
    fun evaluate(context: RiskContext): RiskRuleResult
}

/** Device signals are deliberately local and do not use a hardware identifier or network lookup. */
class DeviceRiskRule : RiskRule {
    override fun evaluate(context: RiskContext): RiskRuleResult = when {
        context.isRooted -> RiskRuleResult(75, "检测到设备完整性风险")
        context.isNewDeviceState -> RiskRuleResult(45, "此设备尚未完成一次主凭据验证")
        else -> RiskRuleResult(0)
    }
}

class BehaviorRiskRule : RiskRule {
    override fun evaluate(context: RiskContext): RiskRuleResult = when {
        context.failedAttempts >= 6 -> RiskRuleResult(30, "近期多次解锁失败")
        context.failedAttempts >= 3 -> RiskRuleResult(20, "近期存在多次解锁失败")
        context.successfulUnlocksInWindow >= 8 &&
            context.nowMillis - context.unlockWindowStartedAt <= RiskEngine.ACCESS_WINDOW_MILLIS ->
            RiskRuleResult(15, "短时间内访问频率较高")
        else -> RiskRuleResult(0)
    }
}

class TimeRiskRule : RiskRule {
    override fun evaluate(context: RiskContext): RiskRuleResult =
        if (context.hourOfDay in 0..5) RiskRuleResult(10, "当前为非常用访问时段") else RiskRuleResult(0)
}

/** Pure scorer kept separate so the rule policy can be regression-tested without Android state. */
object RiskPolicyEvaluator {
    fun evaluate(context: RiskContext, rules: List<RiskRule>): RiskScore {
        val results = rules.map { it.evaluate(context) }
        val score = results.sumOf { it.points }.coerceIn(0, 100)
        val level = when {
            score < 40 -> RiskLevel.LOW
            score < 70 -> RiskLevel.MEDIUM
            else -> RiskLevel.HIGH
        }
        return RiskScore(score, level, results.mapNotNull { it.reason })
    }
}

/**
 * Small, auditable local rule engine for choosing an unlock policy. It does not identify a user,
 * contact a service, or treat a recovery phrase as a normal authentication factor.
 */
class RiskEngine(
    private val preferences: SecurityPreferences,
    private val isRooted: () -> Boolean = RootDetector::isProbablyRooted,
    private val rules: List<RiskRule> = listOf(DeviceRiskRule(), BehaviorRiskRule(), TimeRiskRule())
) {
    suspend fun evaluateNow(nowMillis: Long = System.currentTimeMillis()): RiskScore {
        val signals = preferences.riskSignals()
        val hour = java.util.Calendar.getInstance().apply { timeInMillis = nowMillis }
            .get(java.util.Calendar.HOUR_OF_DAY)
        return evaluate(
            RiskContext(
                isNewDeviceState = !signals.deviceTrusted,
                isRooted = isRooted(),
                failedAttempts = signals.failedAttempts,
                successfulUnlocksInWindow = signals.successfulUnlocksInWindow,
                unlockWindowStartedAt = signals.unlockWindowStartedAt,
                hourOfDay = hour,
                nowMillis = nowMillis
            )
        )
    }

    fun evaluate(context: RiskContext): RiskScore {
        return RiskPolicyEvaluator.evaluate(context, rules)
    }

    suspend fun recordSuccessfulCredentialAuthentication(nowMillis: Long = System.currentTimeMillis()) {
        preferences.recordSuccessfulCredentialAuthentication(nowMillis, ACCESS_WINDOW_MILLIS)
    }

    companion object {
        const val ACCESS_WINDOW_MILLIS = 2 * 60 * 1_000L
    }
}

/** Conservative local root heuristic. A positive result only raises authentication requirements. */
object RootDetector {
    private val knownSuPaths = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk",
        "/system/bin/.ext/.su", "/system/usr/we-need-root/su", "/data/adb/magisk"
    )

    fun isProbablyRooted(): Boolean = try {
        Build.TAGS.orEmpty().contains("test-keys") || knownSuPaths.any { File(it).exists() }
    } catch (_: SecurityException) {
        // Failure to inspect the filesystem must not crash or silently lower authentication.
        true
    } catch (_: Exception) {
        false
    }
}
