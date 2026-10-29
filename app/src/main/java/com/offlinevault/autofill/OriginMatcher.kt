package com.offlinevault.autofill

import java.net.IDN
import java.net.URI
import java.util.Locale

/** Strict origin matching used by autofill. It intentionally never uses substring matching. */
object OriginMatcher {

    /** Scheme used to record the identity of a native Android app a credential belongs to. */
    const val APP_SCHEME = "androidapp://"

    /** A web form must never also match the native browser's saved credentials. */
    fun matchesRequest(storedUrl: String, webDomain: String?, packageName: String?): Boolean =
        if (webDomain != null) matches(storedUrl, webDomain) else matchesApp(storedUrl, packageName)

    fun resolveWebDomain(domains: Collection<String>): String? {
        val normalized = domains.map { requireNotNull(normalizeHost(it)) { "Invalid autofill origin" } }.toSet()
        require(normalized.size <= 1) { "Conflicting autofill origins" }
        return normalized.singleOrNull()
    }

    fun matches(storedUrl: String, requestedDomain: String?): Boolean {
        if (isAppIdentifier(storedUrl)) return false
        val requestedHost = normalizeHost(requestedDomain) ?: return false
        val storedHost = hostFromUrl(storedUrl) ?: return false
        return storedHost == requestedHost
    }

    /** Canonical identifier stored in a credential's url field for a native app. */
    fun appIdentifier(packageName: String): String = APP_SCHEME + packageName.trim()

    /** Matches a stored credential against a native app's package name. Exact, never substring. */
    fun matchesApp(storedUrl: String, requestedPackage: String?): Boolean {
        val pkg = requestedPackage?.trim()?.takeIf { it.isNotEmpty() } ?: return false
        return appPackage(storedUrl) == pkg
    }

    /** True when two stored identifiers point at the same web origin or the same native app. */
    fun sameTarget(a: String, b: String): Boolean {
        val appA = appPackage(a)
        val appB = appPackage(b)
        if (appA != null || appB != null) return appA != null && appA == appB
        val hostA = hostFromUrl(a) ?: return false
        val hostB = hostFromUrl(b) ?: return false
        return hostA == hostB
    }

    /** Namespace web/native identities so imports cannot conflate an app and a like-named site. */
    fun canonicalTarget(value: String): String? =
        appPackage(value)?.let { "app:$it" } ?: hostFromUrl(value)?.let { "host:$it" }

    fun targetLabel(webDomain: String?, packageName: String?): String = when {
        !webDomain.isNullOrBlank() -> {
            val host = normalizeHost(webDomain) ?: "当前网站"
            val requester = packageName?.trim()?.takeIf { it.isNotEmpty() }
            if (requester != null) "$host（由 $requester 请求）" else host
        }
        !packageName.isNullOrBlank() -> packageName.trim()
        else -> "当前目标"
    }

    fun hostFromUrl(value: String): String? {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return null
        if (isAppIdentifier(trimmed)) return null
        val withScheme = if ("://" in trimmed) trimmed else "https://$trimmed"
        return runCatching {
            val uri = URI(withScheme)
            val scheme = uri.scheme?.lowercase(Locale.ROOT)
            if (scheme != "https" && scheme != "http") return null
            val authority = uri.rawAuthority ?: return null
            if ('@' in authority || '%' in authority) return null
            // Autofill supplies a hostname, not a verified port. Never widen a non-default
            // service to every service on that host. Unsupported authorities fail closed.
            val parts = authority.split(':')
            if (parts.size > 2) return null
            if (parts.size == 2) {
                val port = parts[1].toIntOrNull() ?: return null
                if (port != if (scheme == "https") 443 else 80) return null
            }
            normalizeHost(parts[0])
        }.getOrNull()
    }

    internal fun normalizeHost(value: String?): String? {
        val host = value?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT).orEmpty()
        if (host.isEmpty()) return null
        if (host.any { it in ":/\\?#@%" }) return null
        return runCatching { IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES) }
            .getOrNull()
            ?.lowercase(Locale.ROOT)
            ?.takeIf { it.length in 1..253 && it.split('.').all { label -> label.isNotEmpty() } }
    }

    private fun isAppIdentifier(value: String): Boolean =
        value.trim().lowercase(Locale.ROOT).startsWith(APP_SCHEME)

    private fun appPackage(value: String): String? =
        value.trim()
            .takeIf { it.startsWith(APP_SCHEME, ignoreCase = true) }
            ?.substring(APP_SCHEME.length)
            ?.takeIf { it.isNotEmpty() && it.none { char -> char.isWhitespace() || char in "/?#@:" } }
}
