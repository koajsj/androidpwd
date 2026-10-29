package com.offlinevault.security

import java.security.SecureRandom

data class GeneratorOptions(
    val length: Int = 16,
    val useUpper: Boolean = true,
    val useLower: Boolean = true,
    val useDigits: Boolean = true,
    val useSymbols: Boolean = true
)

/** Cryptographically strong, fully offline password generator. */
object PasswordGenerator {

    private const val LOWER = "abcdefghijkmnopqrstuvwxyz"          // no l
    private const val UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"           // no I, O
    private const val DIGITS = "23456789"                         // no 0, 1
    private const val SYMBOLS = "!@#\$%^&*()-_=+[]{};:,.?/"

    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 32

    private val random = SecureRandom()

    fun generatePassphrase(wordCount: Int = 6, separator: String = "-"): String {
        require(wordCount in 6..10) { "口令短语需要 6–10 个单词" }
        require(separator in listOf("-", " ", ".")) { "分隔符无效" }
        val words = MnemonicManager.WORD_LIST
        return List(wordCount) { words[random.nextInt(words.size)] }.joinToString(separator)
    }

    fun passphraseEntropyBits(wordCount: Int): Double {
        require(wordCount in 6..10)
        return wordCount * kotlin.math.log2(MnemonicManager.WORD_LIST.size.toDouble())
    }

    fun generate(options: GeneratorOptions): String {
        val pools = mutableListOf<String>()
        if (options.useLower) pools.add(LOWER)
        if (options.useUpper) pools.add(UPPER)
        if (options.useDigits) pools.add(DIGITS)
        if (options.useSymbols) pools.add(SYMBOLS)

        // Guarantee at least one pool so we never crash.
        if (pools.isEmpty()) pools.add(LOWER)

        val length = options.length.coerceIn(MIN_LENGTH, MAX_LENGTH)
        val all = pools.joinToString("")
        val result = CharArray(length)

        // Ensure at least one character from every selected pool.
        for (i in pools.indices) {
            result[i] = pools[i][random.nextInt(pools[i].length)]
        }
        for (i in pools.size until length) {
            result[i] = all[random.nextInt(all.length)]
        }

        // Fisher-Yates shuffle so the guaranteed characters are not always at the front.
        for (i in result.indices.reversed()) {
            val j = random.nextInt(i + 1)
            val tmp = result[i]; result[i] = result[j]; result[j] = tmp
        }
        return String(result)
    }
}
