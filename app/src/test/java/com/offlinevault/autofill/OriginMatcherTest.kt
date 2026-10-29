package com.offlinevault.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OriginMatcherTest {
    @Test fun webRequestsCannotFallBackToBrowserAppCredentialsOrAmbiguousFrames() {
        val browserAccount = "androidapp://com.example.browser"
        assertFalse(OriginMatcher.matchesRequest(browserAccount, "example.com", "com.example.browser"))
        assertFalse(OriginMatcher.matchesRequest(browserAccount, "invalid/domain", "com.example.browser"))
        assertTrue(OriginMatcher.matchesRequest(browserAccount, null, "com.example.browser"))
        assertEquals("example.com", OriginMatcher.resolveWebDomain(listOf("EXAMPLE.com", "example.com.")))
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { OriginMatcher.resolveWebDomain(listOf("example.com", "evil.test")) }
    }
    @Test fun nativePackageNamesRemainCaseSensitiveAndSeparateFromWebsites() {
        val identifier = OriginMatcher.appIdentifier("com.Example.App")
        assertTrue(OriginMatcher.matchesApp(identifier, "com.Example.App"))
        assertFalse(OriginMatcher.matchesApp(identifier, "com.example.app"))
        assertFalse(OriginMatcher.sameTarget(identifier, "androidapp://com.example.app"))
        assertFalse(OriginMatcher.canonicalTarget(identifier) == OriginMatcher.canonicalTarget("https://com.Example.App"))
    }
    @Test fun aliasesPortsAndMalformedOriginsAreNotSilentlyExpanded() {
        assertFalse(OriginMatcher.matches("https://www.example.com", "example.com"))
        assertFalse(OriginMatcher.sameTarget("https://www.example.com", "example.com"))
        assertFalse(OriginMatcher.matches("https://example.com:8443", "example.com"))
        assertFalse(OriginMatcher.matches("https://user@example.com", "example.com"))
        assertFalse(OriginMatcher.matches("ftp://example.com", "example.com"))
        assertFalse(OriginMatcher.matches("https://example.com", "example.com/path"))
        assertTrue(OriginMatcher.matches("https://example.com:443/path", "example.com"))
        assertTrue(OriginMatcher.matches("https://bücher.example", "xn--bcher-kva.example"))
    }
    @Test fun exactHostMatchingRejectsPhishingSubdomainsAndMissingOrigins() {
        assertTrue(OriginMatcher.matches("https://accounts.example.com/login", "accounts.example.com"))
        assertFalse(OriginMatcher.matches("https://accounts.example.com", "accounts.example.com.evil.test"))
        assertFalse(OriginMatcher.matches("https://example.com", "login.example.com"))
        assertFalse(OriginMatcher.matches("https://login.example.com", "example.com"))
        assertFalse(OriginMatcher.matches("https://example.com", null))
    }

    @Test fun appIdentifiersRequireTheSameNonNullPackage() {
        val id = OriginMatcher.appIdentifier("com.example.app")
        assertTrue(OriginMatcher.matchesApp(id, "com.example.app"))
        assertFalse(OriginMatcher.matchesApp("com.example.app", "com.example.app"))
        assertFalse(OriginMatcher.matchesApp(id, "com.other.app"))
        assertFalse(OriginMatcher.matchesApp(id, null))
    }

    @Test fun sameTargetDistinguishesAppsAndOrigins() {
        val a = OriginMatcher.appIdentifier("com.example.app")
        assertTrue(OriginMatcher.sameTarget(a, OriginMatcher.appIdentifier("com.example.app")))
        assertFalse(OriginMatcher.sameTarget(a, "com.example.app"))
        assertFalse(OriginMatcher.sameTarget(a, "com.other.app"))
        assertTrue(OriginMatcher.sameTarget("https://example.com/login", "example.com"))
        assertFalse(OriginMatcher.sameTarget("https://example.com", a))
        assertFalse(OriginMatcher.matches(a, "com.example.app"))
        assertFalse(OriginMatcher.sameTarget("https://com.example.app", a))
    }

    @Test fun webTargetLabelAlsoNamesRequestingPackage() {
        assertEquals(
            "example.com（由 com.example.browser 请求）",
            OriginMatcher.targetLabel("example.com", "com.example.browser")
        )
    }
}
