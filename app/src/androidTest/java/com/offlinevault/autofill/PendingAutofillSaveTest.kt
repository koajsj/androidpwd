package com.offlinevault.autofill

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PendingAutofillSaveTest {
    @Test
    fun anInFlightCaptureCanRetryEvenIfNewCapturesFilledTheQueue() {
        val older = PendingAutofillSave.Capture("https://synthetic.example", "older", "synthetic")
        assertTrue(PendingAutofillSave.set(older))
        assertEquals(older, PendingAutofillSave.consume())
        val newer = List(4) {
            PendingAutofillSave.Capture("https://synthetic.example", "newer-$it", "synthetic")
        }
        newer.forEach { assertTrue(PendingAutofillSave.set(it)) }
        assertTrue(PendingAutofillSave.retry(older))
        assertEquals(listOf(older) + newer, generateSequence { PendingAutofillSave.consume() }.toList())
    }

    @Test
    fun expiredEntriesDoNotExhaustCapacityForANewCapture() {
        repeat(4) {
            assertTrue(PendingAutofillSave.set(PendingAutofillSave.Capture(
                "https://synthetic.example", "expired-$it", "synthetic", capturedAt = 1L
            )))
        }
        val current = PendingAutofillSave.Capture("https://synthetic.example", "current", "synthetic")
        assertTrue(PendingAutofillSave.set(current))
        assertEquals(current, PendingAutofillSave.consume())
        assertNull(PendingAutofillSave.consume())
    }

    @Before
    @After
    fun drain() {
        while (PendingAutofillSave.consume() != null) { }
    }

    @Test
    fun queuedCapturesAreConsumedInOrderAndOnlyOnce() {
        val captures = List(4) {
            PendingAutofillSave.Capture("https://synthetic.example", "user-$it", "synthetic-$it")
        }
        captures.forEach { assertTrue(PendingAutofillSave.set(it)) }
        val restored = generateSequence { PendingAutofillSave.consume() }.toList()
        assertEquals(captures, restored)
        captures.zip(restored).forEach { (original, decoded) ->
            assertSame(original.receipt, decoded.receipt)
        }
        assertNull(PendingAutofillSave.consume())
    }

    @Test
    fun failedOlderCaptureRetriesBeforeANewerPasswordForTheSameAccount() {
        val older = PendingAutofillSave.Capture("https://synthetic.example", "user", "old-synthetic")
        val newer = older.copy(password = "new-synthetic")
        assertTrue(PendingAutofillSave.set(older))
        assertTrue(PendingAutofillSave.set(newer))
        assertEquals(older, PendingAutofillSave.consume())
        assertTrue(PendingAutofillSave.retry(older))
        assertEquals(older, PendingAutofillSave.consume())
        assertEquals(newer, PendingAutofillSave.consume())
        assertNull(PendingAutofillSave.consume())
    }

    @Test
    fun expiredCaptureDoesNotBlockAValidCaptureOrGainTimeOnRetry() {
        val expired = PendingAutofillSave.Capture(
            "https://synthetic.example", "expired-user", "synthetic", capturedAt = 1L
        )
        val valid = expired.copy(username = "valid-user", capturedAt = System.currentTimeMillis())
        assertTrue(PendingAutofillSave.retry(expired))
        assertTrue(PendingAutofillSave.set(valid))
        assertEquals(valid, PendingAutofillSave.consume())
        assertNull(PendingAutofillSave.consume())
    }
}
