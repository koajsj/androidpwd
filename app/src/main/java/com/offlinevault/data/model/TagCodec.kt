package com.offlinevault.data.model

import com.google.gson.Gson
import java.util.Locale

/**
 * Versioned representation for the plaintext inside the encrypted tags field.
 *
 * Older releases stored comma-separated text. New rows use a JSON array so commas and other
 * punctuation can be part of a tag without changing the Room schema or breaking legacy data.
 */
object TagCodec {
    private const val JSON_PREFIX = "tags-v1:"
    private val gson = Gson()

    fun encode(tags: List<String>): String =
        JSON_PREFIX + gson.toJson(normalize(tags))

    fun decode(value: String): List<String> {
        if (value.isBlank()) return emptyList()
        val tags = if (value.startsWith(JSON_PREFIX)) {
            runCatching {
                gson.fromJson(value.removePrefix(JSON_PREFIX), Array<String>::class.java).toList()
            }.getOrNull() ?: value.split(',')
        } else {
            value.split(',')
        }
        return normalize(tags)
    }

    fun normalize(tags: List<String>): List<String> =
        tags.asSequence()
            .map(String::trim)
            .filter(String::isNotEmpty)
            .distinctBy { it.lowercase(Locale.ROOT) }
            .toList()
}
