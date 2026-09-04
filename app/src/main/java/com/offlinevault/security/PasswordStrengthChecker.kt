package com.offlinevault.security

import java.util.Locale

/** Risk buckets used to colour the UI. */
enum class StrengthLevel { HIGH_RISK, MEDIUM_RISK, LOW_RISK }

data class StrengthResult(
    val score: Int,                 // 0..100
    val level: StrengthLevel,
    val warnings: List<String>
)

/** Non-secret password properties that may safely leave the crypto boundary. */
data class PasswordCharacteristics(
    val length: Int,
    val characterClasses: Int,
    val isCommonWeakPassword: Boolean
)

/**
 * Deterministic, fully offline password strength scorer.
 * Score range 0..100. 0-39 high risk, 40-69 medium risk, 70-100 low risk.
 */
object PasswordStrengthChecker {

    private val COMMON_WEAK = setOf(
        "123456", "12345678", "123456789", "password", "qwerty", "admin",
        "111111", "abc123", "000000", "iloveyou", "1234567", "qwerty123",
        "letmein", "welcome", "monkey", "dragon", "passw0rd", "123123",
        "password1", "qwertyuiop", "1q2w3e4r", "654321", "888888"
    )

    /** Maps a stored 0..100 score to its risk bucket without re-running the full evaluation. */
    fun levelFor(score: Int): StrengthLevel = when {
        score < 40 -> StrengthLevel.HIGH_RISK
        score < 70 -> StrengthLevel.MEDIUM_RISK
        else -> StrengthLevel.LOW_RISK
    }

    /**
     * Returns only aggregate characteristics. Callers must not retain the supplied password after
     * this method returns.
     */
    fun characteristics(password: String): PasswordCharacteristics {
        val classes = listOf(
            password.any { it in 'a'..'z' },
            password.any { it in 'A'..'Z' },
            password.any { it.isDigit() },
            password.any { !it.isLetterOrDigit() }
        ).count { it }
        return PasswordCharacteristics(
            length = password.length,
            characterClasses = classes,
            isCommonWeakPassword = password.lowercase(Locale.ROOT) in COMMON_WEAK
        )
    }

    fun evaluate(password: String): StrengthResult {
        if (password.isEmpty()) {
            return StrengthResult(0, StrengthLevel.HIGH_RISK, listOf("密码不能为空"))
        }

        val warnings = mutableListOf<String>()
        var score = 0

        val characteristics = characteristics(password)
        val length = characteristics.length
        val hasLower = password.any { it in 'a'..'z' }
        val hasUpper = password.any { it in 'A'..'Z' }
        val hasDigit = password.any { it.isDigit() }
        val hasSymbol = password.any { !it.isLetterOrDigit() }
        val onlyDigits = password.all { it.isDigit() }
        val onlyLetters = password.all { it.isLetter() }
        val distinct = password.toSet().size

        // Immediate fail for a known weak password.
        if (characteristics.isCommonWeakPassword) {
            warnings.add("这是非常常见的弱密码")
            return StrengthResult(5, StrengthLevel.HIGH_RISK, warnings)
        }

        // Length scoring (max 40).
        score += when {
            length >= 16 -> 40
            length >= 12 -> 30
            length >= 8 -> 18
            else -> 6
        }
        if (length < 8) warnings.add("密码过短，至少需要 8 个字符")

        // Character class diversity (max 40).
        var classes = 0
        if (hasLower) { score += 8; classes++ }
        if (hasUpper) { score += 10; classes++ } else warnings.add("建议加入大写字母")
        if (hasDigit) { score += 10; classes++ } else warnings.add("建议加入数字")
        if (hasSymbol) { score += 12; classes++ } else warnings.add("建议加入符号")

        // Variety bonus (max 20).
        val varietyRatio = distinct.toFloat() / length.toFloat()
        score += (varietyRatio * 20).toInt()

        // Penalties.
        if (onlyDigits) {
            score -= 25
            warnings.add("仅包含数字，容易被猜到")
        }
        if (onlyLetters) {
            score -= 15
            warnings.add("仅包含字母，建议混合数字和符号")
        }
        if (distinct <= 2) {
            score -= 20
            warnings.add("重复字符过多")
        }
        if (hasSequentialRun(password)) {
            score -= 10
            warnings.add("避免使用 abc 或 123 这类连续字符")
        }
        if (classes <= 1) {
            warnings.add("建议混合使用多种字符类型")
        }

        score = score.coerceIn(0, 100)

        val level = when {
            score < 40 -> StrengthLevel.HIGH_RISK
            score < 70 -> StrengthLevel.MEDIUM_RISK
            else -> StrengthLevel.LOW_RISK
        }
        return StrengthResult(score, level, warnings)
    }

    /** Detects runs of 3+ ascending or descending consecutive characters. */
    private fun hasSequentialRun(password: String): Boolean {
        if (password.length < 3) return false
        var asc = 1
        var desc = 1
        for (i in 1 until password.length) {
            val diff = password[i].code - password[i - 1].code
            asc = if (diff == 1) asc + 1 else 1
            desc = if (diff == -1) desc + 1 else 1
            if (asc >= 3 || desc >= 3) return true
        }
        return false
    }
}
