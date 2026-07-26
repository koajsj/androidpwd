package com.offlinevault.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.KeyStore

/**
 * Wraps an AndroidKeyStore AES key that is bound to biometric authentication.
 *
 * The flow:
 *  - When the user enables biometric unlock we generate a Keystore key that requires user auth.
 *  - We encrypt the DEK with a [Cipher] obtained from [encryptCipher] (gated by BiometricPrompt).
 *  - The resulting IV + ciphertext is stored in DataStore.
 *  - On biometric unlock we obtain [decryptCipher] (also gated by BiometricPrompt) to recover the DEK.
 */
object KeystoreManager {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "offline_vault_biometric_key"
    // Retained only to consume short-lived pending Autofill captures and migrate v1 preferences.
    // Long-lived master/recovery/mnemonic envelopes must never depend on this device key.
    private const val MATERIAL_KEY_ALIAS = "offline_vault_material_key"
    private const val GCM_TAG_BITS = 128
    private const val IV_LENGTH = 12

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun existingKey(alias: String): SecretKey? =
        keyStore().getKey(alias, null) as? SecretKey

    @Synchronized
    private fun getOrCreateKey(): SecretKey {
        existingKey(KEY_ALIAS)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                }
            }
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    @Synchronized
    private fun getOrCreateMaterialKey(): SecretKey {
        existingKey(MATERIAL_KEY_ALIAS)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            MATERIAL_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    /** Deletes only the biometric-bound key and never touches the material-protection key. */
    fun deleteBiometricKey(): Boolean = deleteAlias(KEY_ALIAS)

    /**
     * Deletes the retired v1 material key during an explicit full reset. It is also used for a
     * short-lived pending Autofill capture, so do not delete it automatically while the app runs.
     */
    fun deleteMaterialKeyForFullReset(): Boolean = deleteAlias(MATERIAL_KEY_ALIAS)

    /** Full-reset helper: callers must erase protected preferences before invoking this. */
    fun deleteAllKeysForFullReset(): Boolean =
        deleteBiometricKey() and deleteMaterialKeyForFullReset()

    fun hasKey(): Boolean = runCatching { keyStore().containsAlias(KEY_ALIAS) }.getOrDefault(false)

    fun hasMaterialKey(): Boolean =
        runCatching { keyStore().containsAlias(MATERIAL_KEY_ALIAS) }.getOrDefault(false)

    /** Cipher used to ENCRYPT the DEK. Must be passed to BiometricPrompt before use. */
    fun encryptCipher(): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        return cipher
    }

    /** Recreates only an invalid biometric key; the material-protection key remains untouched. */
    fun recreateBiometricEncryptCipher(): Cipher {
        deleteBiometricKey()
        return encryptCipher()
    }

    /** Cipher used to DECRYPT the DEK with the stored IV. Must be passed to BiometricPrompt. */
    fun decryptCipher(iv: ByteArray): Cipher {
        val key = existingKey(KEY_ALIAS)
            ?: throw IllegalStateException("Biometric key is unavailable")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher
    }

    /** Splits stored blob into IV + ciphertext. */
    fun splitIv(blob: ByteArray): Pair<ByteArray, ByteArray> {
        require(blob.size >= IV_LENGTH + GCM_TAG_BITS / 8) { "Invalid biometric key blob" }
        val iv = blob.copyOfRange(0, IV_LENGTH)
        val ct = blob.copyOfRange(IV_LENGTH, blob.size)
        return iv to ct
    }

    fun joinIv(iv: ByteArray, ciphertext: ByteArray): ByteArray = iv + ciphertext

    fun wrapWithDeviceKey(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMaterialKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        return try {
            joinIv(iv, ciphertext)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    fun unwrapWithDeviceKey(blob: ByteArray): ByteArray {
        val (iv, ciphertext) = splitIv(blob)
        return try {
            val key = existingKey(MATERIAL_KEY_ALIAS)
                ?: throw IllegalStateException("Device material key is unavailable")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.doFinal(ciphertext)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    private fun deleteAlias(alias: String): Boolean = runCatching {
        keyStore().deleteEntry(alias)
        true
    }.getOrDefault(false)
}
