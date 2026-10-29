package com.offlinevault.security

/** A non-secret, one-pass summary of a decrypted credential used for the local health report. */
data class PasswordSecurityCandidate(
    val id: String,
    val strengthScore: Int,
    val passwordFingerprint: String?,
    val passwordLength: Int,
    val characterClasses: Int,
    val isCommonWeakPassword: Boolean,
    val updatedAt: Long
)

enum class PasswordRiskType { WEAK_PASSWORD, REUSED_PASSWORD, STALE_PASSWORD }

enum class SecurityLevel { LOW, MEDIUM, HIGH, CRITICAL }

/** A local finding. It never contains a plaintext password or a stable password hash. */
data class PasswordRisk(
    val type: PasswordRiskType,
    val level: SecurityLevel,
    val affectedCredentialIds: Set<String>,
    val title: String,
    val description: String,
    val recommendation: String
)

data class SecurityReport(
    val totalCredentials: Int,
    val score: Int,
    val level: SecurityLevel,
    val risks: List<PasswordRisk>,
    val recommendations: List<String>,
    val weakCredentialIds: Set<String>,
    val reusedCredentialIds: Set<String>,
    val staleCredentialIds: Set<String>
) {
    companion object {
        fun empty() = SecurityReport(
            totalCredentials = 0,
            score = 100,
            level = SecurityLevel.LOW,
            risks = emptyList(),
            recommendations = emptyList(),
            weakCredentialIds = emptySet(),
            reusedCredentialIds = emptySet(),
            staleCredentialIds = emptySet()
        )
    }
}

/**
 * Fully offline analysis. Length, complexity and uniqueness keep their relative 30:30:20
 * weights. Age is an independent reminder, never evidence that a credential is compromised.
 */
object PasswordSecurityAnalyzer {
    private const val WEAK_SCORE_BELOW = 40
    private const val STALE_AFTER_DAYS = 180L
    private const val MILLIS_PER_DAY = 24L * 60 * 60 * 1_000L

    fun analyze(
        candidates: List<PasswordSecurityCandidate>,
        nowMillis: Long = System.currentTimeMillis()
    ): SecurityReport {
        if (candidates.isEmpty()) return SecurityReport.empty()

        val weakIds = candidates
            .filter {
                it.passwordFingerprint.isNullOrBlank() ||
                    it.isCommonWeakPassword ||
                    it.strengthScore < WEAK_SCORE_BELOW
            }
            .mapTo(linkedSetOf()) { it.id }
        val reusedIds = candidates
            .filter { !it.passwordFingerprint.isNullOrBlank() }
            .groupBy { it.passwordFingerprint }
            .filterValues { it.size > 1 }
            .values
            .flatten()
            .mapTo(linkedSetOf()) { it.id }
        val staleCutoff = nowMillis - STALE_AFTER_DAYS * MILLIS_PER_DAY
        val staleIds = candidates
            .filter { it.updatedAt > 0L && it.updatedAt < staleCutoff }
            .mapTo(linkedSetOf()) { it.id }

        val lengthScore = candidates.map { lengthScore(it.passwordLength) }.average().toInt()
        val complexityScore = candidates.map { complexityScore(it.characterClasses, it.isCommonWeakPassword) }
            .average().toInt()
        // Empty passwords are neither unique nor safe. Do not let a missing fingerprint inflate
        // the uniqueness component simply because it cannot be grouped with another password.
        val uniqueNonEmptyCount = candidates.count {
            !it.passwordFingerprint.isNullOrBlank() && it.id !in reusedIds
        }
        val uniquenessScore = uniqueNonEmptyCount * 100 / candidates.size
        val totalScore = ((lengthScore * 30 + complexityScore * 30 + uniquenessScore * 20) / 80)
            .coerceIn(0, 100)

        val risks = buildList {
            if (weakIds.isNotEmpty()) add(
                PasswordRisk(
                    type = PasswordRiskType.WEAK_PASSWORD,
                    level = SecurityLevel.HIGH,
                    affectedCredentialIds = weakIds,
                    title = "弱密码",
                    description = "存在强度过低或常见密码的账号。",
                    recommendation = "将弱密码替换为至少 12 位且包含多种字符的唯一密码。"
                )
            )
            if (reusedIds.isNotEmpty()) add(
                PasswordRisk(
                    type = PasswordRiskType.REUSED_PASSWORD,
                    level = SecurityLevel.HIGH,
                    affectedCredentialIds = reusedIds,
                    title = "重复使用的密码",
                    description = "多个账号共用了同一个密码。",
                    recommendation = "为每个账号生成并保存不同的密码。"
                )
            )
        }
        return SecurityReport(
            totalCredentials = candidates.size,
            score = totalScore,
            level = levelFor(totalScore),
            risks = risks,
            recommendations = risks.map { it.recommendation }.distinct(),
            weakCredentialIds = weakIds,
            reusedCredentialIds = reusedIds,
            staleCredentialIds = staleIds
        )
    }

    private fun lengthScore(length: Int): Int = when {
        length >= 16 -> 100
        length >= 12 -> 80
        length >= 8 -> 55
        else -> 15
    }

    private fun complexityScore(classes: Int, commonWeak: Boolean): Int {
        if (commonWeak) return 0
        return when (classes) {
            4 -> 100
            3 -> 75
            2 -> 45
            else -> 10
        }
    }

    private fun levelFor(score: Int): SecurityLevel = when {
        score >= 80 -> SecurityLevel.LOW
        score >= 60 -> SecurityLevel.MEDIUM
        score >= 40 -> SecurityLevel.HIGH
        else -> SecurityLevel.CRITICAL
    }
}
