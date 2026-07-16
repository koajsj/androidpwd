package com.offlinevault.autofill

import java.net.IDN
import java.net.URI
import java.util.Locale

/** Strict origin matching used by autofill. It intentionally never uses substring matching. */
object OriginMatcher {

    /** Scheme used to record the identity of a native Android app a credential belongs to. */
    const val APP_SCHEME = "androidapp://"

    fun matches(storedUrl: String, requestedDomain: String?): Boolean {
        if (isAppIdentifier(storedUrl)) return false
        val requestedHost = normalizeHost(requestedDomain) ?: return false
        val storedHost = hostFromUrl(storedUrl) ?: return false
        return storedHost == requestedHost || comparableHost(storedHost) == comparableHost(requestedHost)
    }

    /** Canonical identifier stored in a credential's url field for a native app. */
    fun appIdentifier(packageName: String): String = APP_SCHEME + packageName.trim().lowercase(Locale.ROOT)

    /** Matches a stored credential against a native app's package name. Exact, never substring. */
    fun matchesApp(storedUrl: String, requestedPackage: String?): Boolean {
        val pkg = requestedPackage?.trim()?.lowercase(Locale.ROOT)?.takeIf { it.isNotEmpty() } ?: return false
        val stored = storedUrl.trim().lowercase(Locale.ROOT)
        return stored == APP_SCHEME + pkg
    }

    /** True when two stored identifiers point at the same web origin or the same native app. */
    fun sameTarget(a: String, b: String): Boolean {
        val appA = appPackage(a)
        val appB = appPackage(b)
        if (appA != null || appB != null) return appA != null && appA == appB
        val hostA = hostFromUrl(a) ?: return a.trim().equals(b.trim(), ignoreCase = true)
        val hostB = hostFromUrl(b) ?: return false
        return hostA == hostB || comparableHost(hostA) == comparableHost(hostB)
    }

    fun targetLabel(webDomain: String?, packageName: String?): String = when {
        !webDomain.isNullOrBlank() -> normalizeHost(webDomain) ?: "当前网站"
        !packageName.isNullOrBlank() -> packageName.trim()
        else -> "当前目标"
    }

    fun hostFromUrl(value: String): String? {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return null
        if (isAppIdentifier(trimmed)) return null
        val withScheme = if ("://" in trimmed) trimmed else "https://$trimmed"
        return runCatching { normalizeHost(URI(withScheme).host) }.getOrNull()
    }

    internal fun normalizeHost(value: String?): String? {
        val host = value?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT).orEmpty()
        if (host.isEmpty()) return null
        return runCatching { IDN.toASCII(host) }
            .getOrNull()
            ?.takeIf { it.isNotEmpty() && it.none(Char::isWhitespace) }
    }

    private fun comparableHost(host: String): String = host.removePrefix("www.")

    private fun isAppIdentifier(value: String): Boolean =
        value.trim().lowercase(Locale.ROOT).startsWith(APP_SCHEME)

    private fun appPackage(value: String): String? =
        value.trim()
            .lowercase(Locale.ROOT)
            .takeIf { it.startsWith(APP_SCHEME) }
            ?.removePrefix(APP_SCHEME)
            ?.takeIf { it.isNotEmpty() }
}
