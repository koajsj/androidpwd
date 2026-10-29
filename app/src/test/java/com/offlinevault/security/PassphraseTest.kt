package com.offlinevault.security

import org.junit.Assert.*
import org.junit.Test

class PassphraseTest {
    @Test fun embeddedDictionaryAndEntropyMatchGeneratedWords() {
        val dictionary = MnemonicManager.WORD_LIST
        assertEquals(dictionary.size, dictionary.distinct().size)
        for (count in listOf(6, 8, 10)) {
            for (separator in listOf("-", " ", ".")) {
                val words = PasswordGenerator.generatePassphrase(count, separator).split(separator)
                assertEquals(count, words.size)
                assertTrue(words.all { it in dictionary })
                assertEquals(count * kotlin.math.log2(dictionary.size.toDouble()), PasswordGenerator.passphraseEntropyBits(count), 0.0001)
            }
        }
        assertThrows(IllegalArgumentException::class.java) { PasswordGenerator.generatePassphrase(1) }
    }
}
