package com.offlinevault.security

import org.junit.Assert.*
import org.junit.Test

class TotpTest {
    private val sha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    @Test fun rfc6238VectorsAcrossAlgorithmsAndLargeCounters() {
        val secrets = listOf(sha1,
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=")
        val times = listOf(59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L)
        val expected = listOf(
            listOf("94287082", "46119246", "90693936"), listOf("07081804", "68084774", "25091201"),
            listOf("14050471", "67062674", "99943326"), listOf("89005924", "91819424", "93441116"),
            listOf("69279037", "90698825", "38618901"), listOf("65353130", "77737706", "47863826"))
        times.forEachIndexed { row, time ->
            listOf("SHA1", "SHA256", "SHA512").forEachIndexed { col, algorithm ->
                assertEquals(expected[row][col], Totp.code(TotpConfig(secrets[col], algorithm, 8, 30), time * 1000))
            }
        }
    }
    @Test fun timeBoundaryAndUriValidation() {
        val config = Totp.parse("otpauth://totp/Synthetic?secret=$sha1&digits=6&period=30")
        assertEquals(1, Totp.remainingSeconds(config, 29999))
        assertEquals(30, Totp.remainingSeconds(config, 30000))
        assertEquals(Totp.code(config, 30000), Totp.code(config, 59999))
        assertNotEquals(Totp.code(config, 29999), Totp.code(config, 30000))
        listOf("otpauth://hotp/Test?secret=$sha1", "otpauth://totp/Test?secret=$sha1&secret=$sha1",
            "otpauth://totp/Test?secret=$sha1&algorithm=MD5", "otpauth://totp/Test?secret=$sha1&period=0",
            "otpauth://totp/Test?secret=$sha1&digits=10", "INVALID!", sha1 + "B").forEach { bad ->
            assertThrows(Exception::class.java) { Totp.parse(bad) }
        }
    }
}
