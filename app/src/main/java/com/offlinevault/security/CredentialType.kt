package com.offlinevault.security

/**
 * The kind of unlock credential the user chose at setup. The cryptographic layer is identical for
 * all of them (PBKDF2 over whatever characters are entered) — this only drives input validation and
 * the on-screen keyboard.
 */
enum class CredentialType(
    val key: String,
    val isNumeric: Boolean,
    val minLength: Int,
    val maxLength: Int,
    val displayName: String,
    val noun: String
) {
    PIN4("pin4", true, 4, 4, "4位数字密码", "数字密码"),
    PIN6("pin6", true, 6, 6, "6位数字密码", "数字密码"),
    PASSWORD("password", false, 8, 128, "混合密码", "密码");

    /** True when [value] satisfies this credential's length / character rules. */
    fun isValid(value: String): Boolean =
        if (isNumeric) value.length == minLength && value.all { it.isDigit() }
        else value.length in minLength..maxLength

    /** Filters keystrokes so a PIN only accepts digits and never exceeds its length. */
    fun sanitize(value: String): String =
        if (isNumeric) value.filter { it.isDigit() }.take(maxLength) else value.take(maxLength)

    companion object {
        val setupOptions: List<CredentialType> = entries.toList()

        fun fromKey(key: String?): CredentialType =
            entries.firstOrNull { it.key == key } ?: PIN6
    }
}
