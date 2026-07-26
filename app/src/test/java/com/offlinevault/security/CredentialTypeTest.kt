package com.offlinevault.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialTypeTest {
    @Test fun passwordLengthIsBounded() {
        assertTrue(CredentialType.PASSWORD.isValid("a".repeat(8)))
        assertFalse(CredentialType.PASSWORD.isValid("a".repeat(129)))
        assertEquals(128, CredentialType.PASSWORD.sanitize("a".repeat(200)).length)
    }

    @Test fun newVaultSetupOffersFourDigitPin() {
        assertTrue(CredentialType.PIN4 in CredentialType.setupOptions)
        assertTrue(CredentialType.PIN4.isValid("1234"))
        assertFalse(CredentialType.PIN4.isValid("12345"))
    }
}
