package com.offlinevault.utils

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

object FileIo {
    const val MAX_IMPORT_BYTES = 10 * 1024 * 1024

    /** Uses a no-allocation UTF-8 upper bound so pasted imports obey the same cap as files. */
    fun isTextWithinImportLimit(text: String): Boolean {
        var byteCount = 0
        for (char in text) {
            byteCount += when {
                char.code <= 0x7f -> 1
                char.code <= 0x7ff -> 2
                else -> 3 // surrogate pairs are conservatively counted as two three-byte units
            }
            if (byteCount > MAX_IMPORT_BYTES) return false
        }
        return true
    }

    suspend fun readText(context: Context, uri: Uri): String? = withContext(Dispatchers.IO) {
        try {
            val input = context.contentResolver.openInputStream(uri) ?: return@withContext null
            input.use { readUtf8Limited(it) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        }
    }

    suspend fun writeText(context: Context, uri: Uri, content: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                val bytes = content.toByteArray(Charsets.UTF_8)
                try {
                    val preferredStream = try {
                        context.contentResolver.openOutputStream(uri, "wt")
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        null
                    }
                    if (preferredStream != null) {
                        preferredStream.use {
                            it.write(bytes)
                            it.flush()
                        }
                        return@withContext true
                    }

                    // Some OEM document providers reject the mode argument even though they
                    // support a plain output stream. Keep this fallback in its own `use` block
                    // so both paths deterministically close the provider resource.
                    val fallbackStream = context.contentResolver.openOutputStream(uri)
                        ?: return@withContext false
                    fallbackStream.use {
                        it.write(bytes)
                        it.flush()
                    }
                    true
                } finally {
                    bytes.fill(0)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                false
            }
        }

    internal fun readUtf8Limited(input: InputStream, maxBytes: Int = MAX_IMPORT_BYTES): String {
        val output = ByteArrayOutputStream(minOf(maxBytes, 64 * 1024))
        val buffer = ByteArray(8 * 1024)
        try {
            var total = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                require(total <= maxBytes) { "导入文件超过 ${maxBytes} 字节限制" }
                output.write(buffer, 0, count)
            }
            val bytes = output.toByteArray()
            return try {
                Charsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString()
            } finally {
                bytes.fill(0)
            }
        } finally {
            buffer.fill(0)
        }
    }
}
