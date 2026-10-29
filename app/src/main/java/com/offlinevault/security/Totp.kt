package com.offlinevault.security

import java.net.URI
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class TotpConfig(val secret: String, val algorithm: String, val digits: Int, val period: Int)

/** RFC 6238 / RFC 4226; system time only, no network or persistent generated codes. */
object Totp {
    private const val BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun parse(value: String): TotpConfig {
        require(value.length in 1..2048) { "TOTP 配置长度无效" }
        val input = value.trim()
        val config = if (input.startsWith("otpauth:", ignoreCase = true)) {
            val uri = URI(input)
            require(uri.scheme.equals("otpauth", true) && uri.host.equals("totp", true) &&
                uri.rawUserInfo == null && uri.port == -1 && uri.fragment == null && !uri.path.isNullOrBlank()) {
                "仅支持 TOTP 配置，不支持 HOTP"
            }
            val pairs = uri.rawQuery.orEmpty().split('&').filter { it.isNotEmpty() }.map {
                val pair = it.split('=', limit = 2)
                require(pair.size == 2) { "TOTP 参数无效" }
                URLDecoder.decode(pair[0], "UTF-8") to URLDecoder.decode(pair[1], "UTF-8")
            }
            require(pairs.map { it.first }.distinct().size == pairs.size) { "TOTP 参数重复" }
            val params = pairs.toMap()
            require("counter" !in params) { "不支持 HOTP 计数器" }
            TotpConfig(
                params["secret"].orEmpty(), params["algorithm"] ?: "SHA1",
                params["digits"]?.let { it.toIntOrNull() ?: error("TOTP 位数无效") } ?: 6,
                params["period"]?.let { it.toIntOrNull() ?: error("TOTP 周期无效") } ?: 30
            )
        } else TotpConfig(input, "SHA1", 6, 30)
        val normalized = config.copy(secret = config.secret.uppercase(Locale.ROOT), algorithm = config.algorithm.uppercase(Locale.ROOT))
        validate(normalized)
        return normalized
    }

    private fun validate(config: TotpConfig) {
        require(config.algorithm in setOf("SHA1", "SHA256", "SHA512") &&
            config.digits in 6..8 && config.period in 15..120) { "TOTP 算法、位数或周期不支持" }
        decodeSecret(config.secret).fill(0)
    }

    fun code(config: TotpConfig, nowMillis: Long = System.currentTimeMillis()): String {
        require(nowMillis >= 0) { "系统时间无效" }
        require(config.algorithm in setOf("SHA1", "SHA256", "SHA512") && config.digits in 6..8 && config.period in 15..120)
        val secret = decodeSecret(config.secret)
        val counter = ByteBuffer.allocate(8).putLong(nowMillis / 1000 / config.period).array()
        var digest: ByteArray? = null
        return try {
            val mac = Mac.getInstance("Hmac${config.algorithm}")
            mac.init(SecretKeySpec(secret, mac.algorithm))
            val bytes = mac.doFinal(counter).also { digest = it }
            val offset = bytes.last().toInt() and 15
            val binary = ((bytes[offset].toInt() and 127) shl 24) or
                ((bytes[offset + 1].toInt() and 255) shl 16) or
                ((bytes[offset + 2].toInt() and 255) shl 8) or (bytes[offset + 3].toInt() and 255)
            val divisor = when (config.digits) { 6 -> 1_000_000; 7 -> 10_000_000; else -> 100_000_000 }
            (binary % divisor).toString().padStart(config.digits, '0')
        } finally {
            secret.fill(0)
            counter.fill(0)
            digest?.fill(0)
        }
    }

    fun remainingSeconds(config: TotpConfig, nowMillis: Long): Int =
        config.period - ((nowMillis / 1000) % config.period).toInt()

    private fun decodeSecret(value: String): ByteArray {
        val unpadded = value.trimEnd('=')
        require(unpadded.length in 26..205 && unpadded.length % 8 in setOf(0, 2, 4, 5, 7) &&
            unpadded.all { it in BASE32 }) { "TOTP Base32 密钥无效（至少 128 位）" }
        require(value == unpadded || (value.length % 8 == 0 && value.length - unpadded.length in 1..6)) {
            "TOTP Base32 填充无效"
        }
        val result = ByteArray(unpadded.length * 5 / 8)
        var buffer = 0
        var bits = 0
        var index = 0
        for (c in unpadded) {
            buffer = (buffer shl 5) or BASE32.indexOf(c)
            bits += 5
            if (bits >= 8) {
                bits -= 8
                result[index++] = (buffer shr bits).toByte()
                buffer = buffer and ((1 shl bits) - 1)
            }
        }
        if (buffer != 0) {
            result.fill(0)
            throw IllegalArgumentException("TOTP Base32 尾部无效")
        }
        return result
    }
}
