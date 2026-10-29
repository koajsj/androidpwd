package com.offlinevault.autofill

import com.offlinevault.security.KeystoreManager
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Holds credentials captured by the autofill Save flow while the vault is locked.
 *
 * Only Keystore-encrypted bytes live in process memory between callbacks. They are consumed and
 * encrypted into the vault after the next unlock. If the process dies before then, the pending
 * save is dropped rather than being persisted in the clear.
 */
object PendingAutofillSave {

    data class Capture(
        val identifier: String,
        val username: String,
        val password: String,
        val capturedAt: Long = System.currentTimeMillis()
    ) {
        // Shared with the encrypted queue entry, never the plaintext Capture itself.
        internal var receipt = SaveReceipt()
    }

    internal class SaveReceipt {
        @Volatile var saved = false
        @Volatile var outcomeUnknown = false
    }

    private const val MAX_PENDING_AGE_MS = 5 * 60 * 1000L
    private const val MAX_FIELD_BYTES = 64 * 1024
    private const val MAX_PENDING_CAPTURES = 4

    private data class PendingCapture(
        val encryptedCapture: ByteArray,
        val receipt: SaveReceipt,
        val createdAt: Long = System.currentTimeMillis()
    )

    private val pending = ArrayDeque<PendingCapture>()

    /**
     * Queues one captured credential for the immediate post-unlock save. Failure to use the
     * device Keystore intentionally drops the capture instead of retaining sensitive plaintext.
     */
    fun set(capture: Capture): Boolean = enqueue(capture, first = false)

    /** A failed older save must retry before newer captures for the same account. */
    fun retry(capture: Capture): Boolean = enqueue(capture, first = true)

    @Synchronized
    private fun enqueue(capture: Capture, first: Boolean): Boolean {
        val now = System.currentTimeMillis()
        // Expired captures must not monopolize the bounded queue while the vault stays locked.
        pending.removeAll { entry ->
            val age = now - entry.createdAt
            (age < 0 || age > MAX_PENDING_AGE_MS).also { expired ->
                if (expired) entry.encryptedCapture.fill(0)
            }
        }
        // A single consumer may be writing while four new captures arrive. Reserve one bounded
        // retry slot so cancellation/failure can put that in-flight capture back at the head.
        val capacity = MAX_PENDING_CAPTURES + if (first) 1 else 0
        if (pending.size >= capacity) return false
        val plain = try {
            encode(capture)
        } catch (_: Exception) {
            // AssistStructure comes from another app. A malformed or oversized field must only
            // drop this optional deferred save, never crash the Autofill service process.
            return false
        }
        val encrypted = try {
            KeystoreManager.wrapWithDeviceKey(plain)
        } catch (_: Exception) {
            plain.fill(0)
            return false
        }
        plain.fill(0)
        val entry = PendingCapture(encrypted, capture.receipt, capture.capturedAt)
        if (first) pending.addFirst(entry) else pending.addLast(entry)
        return true
    }

    /** Returns the oldest pending capture (if any) and removes it. */
    @Synchronized
    fun consume(): Capture? {
        while (true) {
            val current = pending.removeFirstOrNull() ?: return null
            val age = System.currentTimeMillis() - current.createdAt
            if (age < 0 || age > MAX_PENDING_AGE_MS) {
                current.encryptedCapture.fill(0)
                continue
            }
            val plain = try {
                KeystoreManager.unwrapWithDeviceKey(current.encryptedCapture)
            } catch (_: Exception) {
                continue
            } finally {
                current.encryptedCapture.fill(0)
            }
            try {
                return decode(plain).copy(capturedAt = current.createdAt).also {
                    it.receipt = current.receipt
                }
            } catch (_: Exception) {
                // An invalid entry must not hide a later valid capture.
            } finally {
                plain.fill(0)
            }
        }
    }

    private fun encode(capture: Capture): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream ->
            stream.writeField(capture.identifier)
            stream.writeField(capture.username)
            stream.writeField(capture.password)
        }
        return output.toByteArray()
    }

    private fun decode(bytes: ByteArray): Capture =
        DataInputStream(ByteArrayInputStream(bytes)).use { stream ->
            Capture(
                identifier = stream.readField(),
                username = stream.readField(),
                password = stream.readField()
            )
        }

    private fun DataOutputStream.writeField(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        try {
            require(bytes.size <= MAX_FIELD_BYTES) { "Autofill field is too large" }
            writeInt(bytes.size)
            write(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun DataInputStream.readField(): String {
        val size = readInt()
        require(size in 0..MAX_FIELD_BYTES) { "Invalid autofill field length" }
        val bytes = ByteArray(size)
        return try {
            readFully(bytes)
            String(bytes, Charsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }
}
