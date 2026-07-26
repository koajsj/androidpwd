package com.offlinevault.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OriginMatcherTest {
    @Test fun exactHostMatches() {
        assertTrue(OriginMatcher.matches("https://accounts.example.com/login", "accounts.example.com"))
    }

    @Test fun phishingSuffixDoesNotMatch() {
        assertFalse(OriginMatcher.matches("https://accounts.example.com", "accounts.example.com.evil.test"))
    }

    @Test fun parentAndSubdomainDoNotCrossMatch() {
        assertFalse(OriginMatcher.matches("https://example.com", "login.example.com"))
        assertFalse(OriginMatcher.matches("https://login.example.com", "example.com"))
    }

    @Test fun missingOriginNeverMatches() {
        assertFalse(OriginMatcher.matches("https://example.com", null))
    }

    @Test fun appIdentifierMatchesSamePackage() {
        val id = OriginMatcher.appIdentifier("com.example.app")
        assertTrue(OriginMatcher.matchesApp(id, "com.example.app"))
        assertFalse(OriginMatcher.matchesApp("com.example.app", "com.example.app"))
    }

    @Test fun appIdentifierRejectsDifferentPackageAndNull() {
        val id = OriginMatcher.appIdentifier("com.example.app")
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
    }

    @Test fun webRequestsNeverMatchAppIdentifiers() {
        val appId = OriginMatcher.appIdentifier("com.example.app")
        assertFalse(OriginMatcher.matches(appId, "com.example.app"))
        assertFalse(OriginMatcher.sameTarget("https://com.example.app", appId))
    }

    @Test fun webTargetLabelAlsoNamesRequestingPackage() {
        assertEquals(
            "example.com（由 com.example.browser 请求）",
            OriginMatcher.targetLabel("example.com", "com.example.browser")
        )
    }
}
