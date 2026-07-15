package com.offlinevault.autofill

import com.offlinevault.security.KeystoreManager
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Holds one credential captured by the autofill Save flow while the vault is locked.
 *
 * Only Keystore-encrypted bytes live in process memory between callbacks. They are consumed and
 * encrypted into the vault after the next unlock. If the process dies before then, the pending
 * save is dropped rather than being persisted in the clear.
 */
object PendingAutofillSave {

    data class Capture(val identifier: String, val username: String, val password: String)

    private const val MAX_PENDING_AGE_MS = 5 * 60 * 1000L
    private const val MAX_FIELD_BYTES = 64 * 1024

    private data class PendingCapture(
        val encryptedCapture: ByteArray,
        val createdAt: Long = System.currentTimeMillis()
    )

    private var pending: PendingCapture? = null

    /**
     * Queues one captured credential for the immediate post-unlock save. Failure to use the
     * device Keystore intentionally drops the capture instead of retaining sensitive plaintext.
     */
    @Synchronized
    fun set(capture: Capture): Boolean {
        val plain = encode(capture)
        val encrypted = try {
            KeystoreManager.wrapWithDeviceKey(plain)
        } catch (_: Exception) {
            plain.fill(0)
            return false
        }
        plain.fill(0)
        pending?.encryptedCapture?.fill(0)
        pending = PendingCapture(encrypted)
        return true
    }

    /** Returns the pending capture (if any) and clears it. */
    @Synchronized
    fun consume(): Capture? {
        val current = pending
        pending = null
        if (current == null) return null
        val expired = System.currentTimeMillis() - current.createdAt > MAX_PENDING_AGE_MS
        if (expired) {
            current.encryptedCapture.fill(0)
            return null
        }
        val plain = try {
            KeystoreManager.unwrapWithDeviceKey(current.encryptedCapture)
        } catch (_: Exception) {
            current.encryptedCapture.fill(0)
            return null
        }
        current.encryptedCapture.fill(0)
        return try {
            decode(plain)
        } catch (_: Exception) {
            null
        } finally {
            plain.fill(0)
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
