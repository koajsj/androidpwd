package com.offlinevault.security

import com.offlinevault.data.preferences.SecurityPreferences
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.InvalidKeyException
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey

/** Outcome of an unlock attempt. */
sealed interface UnlockResult {
    object Success : UnlockResult
    object WrongCredential : UnlockResult
    data class Delayed(val secondsRemaining: Int) : UnlockResult
    data class Error(val message: String) : UnlockResult
}

/**
 * High level key lifecycle: first-time setup, unlock, recovery, master-password change and the
 * biometric wrapping orchestration. All persistence goes through [SecurityPreferences]; the live
 * key lives only in [SessionManager].
 *
 * Envelope encryption model:
 *   DEK (random 256-bit)  ── wrapped by ──▶  master key  = PBKDF2(masterPassword, masterSalt)
 *                          └─ wrapped by ──▶ recovery key = PBKDF2(randomMnemonic, mnemonicSalt)
 * Security answers are not accepted as a recovery or DEK-unwrapping credential.
 * The DEK and credentials are never stored in the clear.
 */
class KeyManager(
    private val prefs: SecurityPreferences,
    private val mnemonicManager: MnemonicManager
) {
    companion object {
        private const val DEVICE_WRAPPED_PREFIX = "ks:v1:"
        private const val MNEMONIC_REAUTH_WINDOW_MILLIS = 5 * 60 * 1_000L
    }

    private data class MnemonicUpdateAuthorization(
        val sessionGeneration: Long,
        val expiresAtMillis: Long
    )

    /** In-memory, single-use proof of a recent master-password reauthentication. */
    private var mnemonicUpdateAuthorization: MnemonicUpdateAuthorization? = null

    private data class BiometricAuthorization(
        val cipher: Cipher,
        val sessionGeneration: Long,
        val wrappedDek: String? = null
    )

    private val credentialMutex = Mutex()
    private var biometricUnlockAuthorization: BiometricAuthorization? = null
    private var biometricEnableAuthorization: BiometricAuthorization? = null

    // Serialize verification with credential replacement. Do not recheck after a successful
    // persistent write: a later lock must not turn an acknowledged commit into a retryable error.
    private suspend fun <T> credentialOperation(block: suspend () -> T): T {
        val generation = SessionManager.sessionGeneration
        return credentialMutex.withLock {
            if (generation != SessionManager.sessionGeneration) {
                throw VaultLockedException("Authentication session expired")
            }
            block()
        }
    }

    /** Returns whether this initialization also established an unlocked session. */
    suspend fun setup(
        masterPassword: String,
        mnemonicPhrase: String,
        credentialType: CredentialType = CredentialType.PASSWORD
    ): Boolean = credentialOperation {
        setupInternal(masterPassword, mnemonicPhrase, credentialType)
    }

    suspend fun unlockWithPassword(masterPassword: String): UnlockResult =
        credentialOperation { unlockWithPasswordInternal(masterPassword) }

    suspend fun recoverWithMnemonic(mnemonicPhrase: String, newMasterPassword: String): UnlockResult =
        credentialOperation { recoverWithMnemonicInternal(mnemonicPhrase, newMasterPassword) }

    suspend fun changeMasterPassword(oldPassword: String, newPassword: String): UnlockResult =
        credentialOperation { changeMasterPasswordInternal(oldPassword, newPassword) }

    suspend fun verifyMasterCredential(masterPassword: String): UnlockResult =
        credentialOperation { verifyMasterCredentialInternal(masterPassword) }

    suspend fun authorizeMnemonicRecoveryUpdate(masterPassword: String): UnlockResult =
        credentialOperation { authorizeMnemonicRecoveryUpdateInternal(masterPassword) }

    suspend fun updateMnemonicRecoveryForUnlockedSession(mnemonicPhrase: String): UnlockResult =
        credentialOperation { updateMnemonicRecoveryForUnlockedSessionInternal(mnemonicPhrase) }

    suspend fun disableMnemonicRecovery(masterPassword: String): UnlockResult =
        credentialOperation { disableMnemonicRecoveryInternal(masterPassword) }

    /** First launch: only the normal credential and a random mnemonic may wrap the new DEK. */
    private suspend fun setupInternal(
        masterPassword: String,
        mnemonicPhrase: String,
        credentialType: CredentialType
    ): Boolean {
        val generation = SessionManager.sessionGeneration
        require(masterPassword.isNotBlank() && credentialType.isValid(masterPassword)) { "解锁凭据格式无效" }
        val normalizedMnemonic = mnemonicManager.normalize(mnemonicPhrase)
        require(mnemonicManager.isValidPhrase(normalizedMnemonic)) { "助记词格式无效" }
        val dek = CryptoManager.newDataEncryptionKey()

        val masterSalt = CryptoManager.newSalt()
        var masterWrapped = ByteArray(0)
        var dekTransferredToSession = false
        try {
            val kdf = KdfVersions.current()
            masterWrapped = wrapDekWithSecret(masterPassword, masterSalt, kdf, dek)
            val mnemonic = prepareMnemonicMaterial(dek, normalizedMnemonic)
            prefs.saveVaultMaterial(
                masterSalt = CryptoManager.encode(masterSalt),
                masterWrappedDek = encodeWrappedDek(masterWrapped),
                masterIterations = kdf.iterations,
                masterKdfVersion = kdf.version,
                mnemonic = mnemonic,
                credentialType = credentialType.key
            )
            try {
                SessionManager.unlock(dek, generation)
                dekTransferredToSession = true
            } catch (_: VaultLockedException) {
                // Initialization is already durable. Leave it locked rather than inviting a
                // retry which could overwrite the just-created vault's only DEK envelopes.
            }
            return dekTransferredToSession
        } finally {
            masterSalt.fill(0)
            masterWrapped.fill(0)
            if (!dekTransferredToSession) CryptoManager.destroyKey(dek)
        }
    }

    /** How many seconds the user must still wait before another attempt is allowed. */
    suspend fun unlockDelaySeconds(): Int {
        return UnlockThrottle.remainingSeconds(
            attempts = prefs.failedAttempts(),
            lastFailedAt = prefs.lastFailedAt(),
            now = System.currentTimeMillis()
        )
    }

    private suspend fun unlockWithPasswordInternal(masterPassword: String): UnlockResult {
        val generation = SessionManager.sessionGeneration
        val delay = unlockDelaySeconds()
        if (delay > 0) return UnlockResult.Delayed(delay)

        val saltB64 = prefs.masterSalt() ?: return UnlockResult.Error("密码库尚未初始化")
        val wrappedDek = masterWrappedDekBytes() ?: return UnlockResult.Error("密码库尚未初始化")

        val salt = try {
            CryptoManager.decode(saltB64)
        } catch (_: Exception) {
            wrappedDek.fill(0)
            return UnlockResult.Error("无法读取加密密钥，数据可能已损坏")
        }
        return try {
            val dekBytes = decryptWithSecret(masterPassword, salt, masterKdfSpec(), wrappedDek)
            val dek = secretKeyFromBytes(dekBytes)
            var transferred = false
            try {
                prefs.resetFailures()
                SessionManager.unlock(dek, generation)
                transferred = true
                UnlockResult.Success
            } finally {
                if (!transferred) CryptoManager.destroyKey(dek)
            }
        } catch (e: AEADBadTagException) {
            prefs.recordFailure()
            UnlockResult.WrongCredential
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            UnlockResult.Error("无法读取加密密钥，数据可能已损坏")
        } finally {
            salt.fill(0)
            wrappedDek.fill(0)
        }
    }

    /** Final recovery path: 12-word phrase recovers the DEK and only resets the master password. */
    private suspend fun recoverWithMnemonicInternal(mnemonicPhrase: String, newMasterPassword: String): UnlockResult {
        val generation = SessionManager.sessionGeneration
        if (!validReplacementCredential(newMasterPassword)) return UnlockResult.Error("新解锁凭据格式无效")
        val delay = unlockDelaySeconds()
        if (delay > 0) return UnlockResult.Delayed(delay)

        val saltB64 = prefs.mnemonicSalt() ?: return UnlockResult.Error("未启用助记词恢复")
        val wrappedDek = mnemonicWrappedDekBytes(migrate = false) ?: return UnlockResult.Error("未启用助记词恢复")
        try {
            val verifierHash = mnemonicVerifierHash(migrate = false) ?: return UnlockResult.Error("未启用助记词恢复")
            val normalizedMnemonic = mnemonicManager.normalize(mnemonicPhrase)
            if (!mnemonicManager.isValidPhrase(normalizedMnemonic)) {
                prefs.recordFailure()
                return UnlockResult.WrongCredential
            }

            val mnemonicKdf = mnemonicKdfSpec()
            val dekBytes = try {
                val salt = CryptoManager.decode(saltB64)
                try {
                    if (!mnemonicManager.verifierMatches(normalizedMnemonic, salt, verifierHash, mnemonicKdf)) {
                        prefs.recordFailure()
                        return UnlockResult.WrongCredential
                    }
                    val mnemonicKey = mnemonicManager.deriveRecoveryKey(normalizedMnemonic, salt, mnemonicKdf)
                    try {
                        CryptoManager.decrypt(mnemonicKey, wrappedDek)
                    } finally {
                        CryptoManager.destroyKey(mnemonicKey)
                    }
                } finally {
                    salt.fill(0)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: AEADBadTagException) {
                prefs.recordFailure()
                return UnlockResult.WrongCredential
            } catch (_: Exception) {
                return UnlockResult.Error("无法读取助记词恢复密钥，数据可能已损坏")
            }

            val dek = secretKeyFromBytes(dekBytes)
            return try {
                invalidateCredentialAuthorizations()
                val recoveryGeneration = SessionManager.beginRecovery(generation)
                // Commit any verified legacy outer-envelope migration together with the new
                // master wrapper; failed recovery must not rewrite either piece in isolation.
                val mnemonic = SecurityPreferences.MnemonicMaterial(
                    saltB64, encodeWrappedDek(wrappedDek), verifierHash,
                    mnemonicKdf.iterations, mnemonicKdf.version
                )
                completeRecovery(dek, newMasterPassword, recoveryGeneration, mnemonic)
                // A valid recovery phrase may reset the master credential only; it must not
                // become a second, implicit daily-unlock path.
                UnlockResult.Success
            } finally {
                CryptoManager.destroyKey(dek)
            }
        } finally {
            wrappedDek.fill(0)
        }
    }

    /** Change master password: verify the old one, then re-wrap the DEK under the new one. */
    private suspend fun changeMasterPasswordInternal(oldPassword: String, newPassword: String): UnlockResult {
        if (!validReplacementCredential(newPassword)) return UnlockResult.Error("新解锁凭据格式无效")
        val delay = unlockDelaySeconds()
        if (delay > 0) return UnlockResult.Delayed(delay)

        val saltB64 = prefs.masterSalt() ?: return UnlockResult.Error("密码库尚未初始化")
        val wrappedDek = masterWrappedDekBytes() ?: return UnlockResult.Error("密码库尚未初始化")

        val salt = try {
            CryptoManager.decode(saltB64)
        } catch (_: Exception) {
            wrappedDek.fill(0)
            return UnlockResult.Error("无法读取加密密钥，数据可能已损坏")
        }
        val dekBytes = try {
            decryptWithSecret(oldPassword, salt, masterKdfSpec(), wrappedDek)
        } catch (e: CancellationException) {
            throw e
        } catch (_: AEADBadTagException) {
            prefs.recordFailure()
            return UnlockResult.WrongCredential
        } catch (_: Exception) {
            return UnlockResult.Error("无法读取加密密钥，数据可能已损坏")
        } finally {
            salt.fill(0)
            wrappedDek.fill(0)
        }
        val dek = secretKeyFromBytes(dekBytes)
        return try {
            invalidateCredentialAuthorizations()
            rewrapMaster(dek, newPassword, resetFailures = true)
            UnlockResult.Success
        } finally {
            CryptoManager.destroyKey(dek)
        }
    }

    /** Verifies the current master credential without unlocking or exposing the DEK to callers. */
    private suspend fun verifyMasterCredentialInternal(masterPassword: String): UnlockResult {
        val delay = unlockDelaySeconds()
        if (delay > 0) return UnlockResult.Delayed(delay)

        val saltB64 = prefs.masterSalt() ?: return UnlockResult.Error("密码库尚未初始化")
        val wrappedDek = masterWrappedDekBytes() ?: return UnlockResult.Error("密码库尚未初始化")

        val salt = try {
            CryptoManager.decode(saltB64)
        } catch (_: Exception) {
            wrappedDek.fill(0)
            return UnlockResult.Error("无法读取加密密钥，数据可能已损坏")
        }
        return try {
            val dekBytes = decryptWithSecret(masterPassword, salt, masterKdfSpec(), wrappedDek)
            dekBytes.fill(0)
            prefs.resetFailures()
            UnlockResult.Success
        } catch (e: CancellationException) {
            throw e
        } catch (_: AEADBadTagException) {
            prefs.recordFailure()
            UnlockResult.WrongCredential
        } catch (_: Exception) {
            UnlockResult.Error("无法读取加密密钥，数据可能已损坏")
        } finally {
            salt.fill(0)
            wrappedDek.fill(0)
        }
    }

    /** Creates an in-memory, short-lived and single-use authorization for a mnemonic update. */
    private suspend fun authorizeMnemonicRecoveryUpdateInternal(masterPassword: String): UnlockResult {
        if (!SessionManager.isUnlocked) return UnlockResult.Error("密码库已锁定，请重新解锁")
        val generation = SessionManager.requireActiveSession()
        mnemonicUpdateAuthorization = null
        val result = verifyMasterCredentialInternal(masterPassword)
        if (result is UnlockResult.Success) {
            try {
                SessionManager.withActiveSessionNow(generation) {
                    mnemonicUpdateAuthorization = MnemonicUpdateAuthorization(
                        sessionGeneration = generation,
                        expiresAtMillis = monotonicMillis() + MNEMONIC_REAUTH_WINDOW_MILLIS
                    )
                }
            } catch (_: VaultLockedException) {
                return UnlockResult.Error("密码库已锁定，请重新解锁")
            }
        }
        return result
    }

    /** Consumes the recent master-password authorization before replacing mnemonic material. */
    private suspend fun updateMnemonicRecoveryForUnlockedSessionInternal(mnemonicPhrase: String): UnlockResult {
        val authorization = mnemonicUpdateAuthorization.also { mnemonicUpdateAuthorization = null }
        if (authorization == null ||
            authorization.expiresAtMillis <= monotonicMillis() ||
            authorization.sessionGeneration != SessionManager.sessionGeneration ||
            !SessionManager.isUnlocked
        ) {
            return UnlockResult.Error("请先验证当前主密码")
        }
        if (!mnemonicManager.isValidPhrase(mnemonicPhrase)) return UnlockResult.Error("助记词格式无效")
        return try {
            SessionManager.withCredentialWrite { generation ->
                SessionManager.requireActiveSession(authorization.sessionGeneration)
                updateMnemonicRecoveryForDek(SessionManager.requireKey(), mnemonicPhrase, generation)
            }
            UnlockResult.Success
        } catch (e: CancellationException) {
            throw e
        } catch (_: VaultLockedException) {
            UnlockResult.Error("密码库已锁定，请重新解锁")
        } catch (_: Exception) {
            UnlockResult.Error("无法更新助记词恢复信息，请重试")
        }
    }

    private suspend fun updateMnemonicRecoveryForDek(
        dek: SecretKey,
        mnemonicPhrase: String,
        generation: Long
    ) {
        val material = prepareMnemonicMaterial(dek, mnemonicPhrase)
        prefs.updateMnemonicMaterial(material, generation)
    }

    /** Validate the replacement envelope before allowing any old recovery material to retire. */
    private fun prepareMnemonicMaterial(dek: SecretKey, mnemonicPhrase: String): SecurityPreferences.MnemonicMaterial {
        val normalizedMnemonic = mnemonicManager.normalize(mnemonicPhrase)

        val salt = CryptoManager.newSalt()
        try {
            val mnemonicKdf = KdfVersions.current()
            val mnemonicKey = mnemonicManager.deriveRecoveryKey(normalizedMnemonic, salt, mnemonicKdf)
            val wrapped = try {
                val encrypted = wrapDek(mnemonicKey, dek)
                try {
                    val recovered = CryptoManager.decrypt(mnemonicKey, encrypted)
                    val original = dek.encoded
                    try {
                        check(MessageDigest.isEqual(original, recovered)) { "Recovery envelope verification failed" }
                    } finally {
                        recovered.fill(0)
                        original.fill(0)
                    }
                    encrypted
                } catch (e: Exception) {
                    encrypted.fill(0)
                    throw e
                }
            } finally {
                CryptoManager.destroyKey(mnemonicKey)
            }
            try {
                return SecurityPreferences.MnemonicMaterial(
                    salt = CryptoManager.encode(salt),
                    wrappedDek = encodeWrappedDek(wrapped),
                    verifierHash = mnemonicManager.verifierHash(normalizedMnemonic, salt, mnemonicKdf),
                    iterations = mnemonicKdf.iterations,
                    kdfVersion = mnemonicKdf.version
                )
            } finally {
                wrapped.fill(0)
            }
        } finally {
            salt.fill(0)
        }
    }

    private suspend fun disableMnemonicRecoveryInternal(masterPassword: String): UnlockResult {
        val generation = SessionManager.requireActiveSession()
        val delay = unlockDelaySeconds()
        if (delay > 0) return UnlockResult.Delayed(delay)

        // Disabling only needs proof of the current master credential. Avoid materialising a
        // second DEK object solely for this confirmation action.
        when (val verification = verifyMasterCredentialInternal(masterPassword)) {
            is UnlockResult.Success -> Unit
            else -> return verification
        }
        SessionManager.requireActiveSession(generation)
        prefs.clearMnemonicMaterial(generation)
        mnemonicUpdateAuthorization = null
        return UnlockResult.Success
    }

    private suspend fun validReplacementCredential(value: String): Boolean =
        value.isNotBlank() && CredentialType.fromKey(prefs.credentialTypeFlow.first()).isValid(value)

    private fun monotonicMillis(): Long = System.nanoTime() / 1_000_000

    private fun invalidateCredentialAuthorizations() {
        mnemonicUpdateAuthorization = null
        biometricUnlockAuthorization = null
        biometricEnableAuthorization = null
    }

    private suspend fun completeRecovery(
        dek: SecretKey,
        newPassword: String,
        generation: Long,
        mnemonic: SecurityPreferences.MnemonicMaterial
    ) {
        val salt = CryptoManager.newSalt()
        try {
            val kdf = KdfVersions.current()
            val wrapped = wrapDekWithSecret(newPassword, salt, kdf, dek)
            try {
                prefs.completeRecovery(CryptoManager.encode(salt), encodeWrappedDek(wrapped),
                    kdf.iterations, kdf.version, generation, mnemonic)
            } finally {
                wrapped.fill(0)
            }
        } finally {
            salt.fill(0)
        }
    }

    private suspend fun rewrapMaster(
        dek: SecretKey,
        newPassword: String,
        resetFailures: Boolean = false
    ) {
        val salt = CryptoManager.newSalt()
        try {
            val kdf = KdfVersions.current()
            val wrapped = wrapDekWithSecret(newPassword, salt, kdf, dek)
            try {
                if (resetFailures) {
                    prefs.updateMasterMaterialAndResetFailures(
                        masterSalt = CryptoManager.encode(salt),
                        masterWrappedDek = encodeWrappedDek(wrapped),
                        masterIterations = kdf.iterations,
                        masterKdfVersion = kdf.version
                    )
                } else {
                    prefs.updateMasterMaterial(
                        masterSalt = CryptoManager.encode(salt),
                        masterWrappedDek = encodeWrappedDek(wrapped),
                        masterIterations = kdf.iterations,
                        masterKdfVersion = kdf.version
                    )
                }
            } finally {
                wrapped.fill(0)
            }
        } finally {
            salt.fill(0)
        }
    }

    private fun deriveKeyFromSecret(secret: String, salt: ByteArray, kdf: KdfSpec): SecretKey {
        val chars = secret.toCharArray()
        return try {
            CryptoManager.deriveKey(chars, salt, kdf)
        } finally {
            chars.fill('\u0000')
        }
    }

    private fun decryptWithSecret(
        secret: String,
        salt: ByteArray,
        kdf: KdfSpec,
        wrapped: ByteArray
    ): ByteArray {
        val key = deriveKeyFromSecret(secret, salt, kdf)
        return try {
            CryptoManager.decrypt(key, wrapped)
        } finally {
            CryptoManager.destroyKey(key)
        }
    }

    private fun wrapDekWithSecret(
        secret: String,
        salt: ByteArray,
        kdf: KdfSpec,
        dek: SecretKey
    ): ByteArray {
        val key = deriveKeyFromSecret(secret, salt, kdf)
        return try {
            wrapDek(key, dek)
        } finally {
            CryptoManager.destroyKey(key)
        }
    }

    // ---- Biometric ---------------------------------------------------------

    /** Prepare while the original session is active, not when the prompt eventually returns. */
    suspend fun biometricEncryptCipher(): Cipher? = credentialOperation {
        val generation = SessionManager.requireActiveSession()
        biometricEnableAuthorization = null
        val cipher = try {
            KeystoreManager.encryptCipher()
        } catch (_: InvalidKeyException) {
            // Only an unusable key may be replaced; cancelling a prompt never deletes a valid key.
            KeystoreManager.recreateBiometricEncryptCipher()
        }
        SessionManager.withActiveSessionNow(generation) {
            biometricEnableAuthorization = BiometricAuthorization(cipher, generation)
        }
        cipher
    }

    /**
     * Persists the DEK wrapped by the biometric-bound Keystore key.
     * [authenticatedCipher] must already have passed through BiometricPrompt in ENCRYPT mode.
     */
    suspend fun storeBiometricWrappedDek(authenticatedCipher: Cipher) = credentialOperation {
        val authorization = biometricEnableAuthorization
        biometricEnableAuthorization = null
        check(authorization != null && authorization.cipher === authenticatedCipher) {
            "Biometric authorization is unavailable"
        }
        SessionManager.withCredentialWrite { generation ->
            SessionManager.requireActiveSession(authorization.sessionGeneration)
            val dekBytes = SessionManager.requireKey().encoded
            val ciphertext = try {
                authenticatedCipher.doFinal(dekBytes)
            } finally {
                dekBytes.fill(0)
            }
            val iv = authenticatedCipher.iv
            val blob = KeystoreManager.joinIv(iv, ciphertext)
            try {
                prefs.setBiometric(enabled = true, wrappedDek = CryptoManager.encode(blob), expectedGeneration = generation)
            } finally {
                iv.fill(0)
                ciphertext.fill(0)
                blob.fill(0)
            }
        }
    }

    suspend fun disableBiometric(): Unit = credentialOperation {
        biometricUnlockAuthorization = null
        biometricEnableAuthorization = null
        prefs.setBiometric(enabled = false, wrappedDek = null)
        KeystoreManager.deleteBiometricKey()
    }

    /** Builds a decrypt cipher (gated by biometrics) for the stored wrapped DEK, or null if unavailable. */
    suspend fun biometricDecryptCipher(): Cipher? = credentialOperation { biometricDecryptCipherInternal() }

    private suspend fun biometricDecryptCipherInternal(): Cipher? {
        val generation = SessionManager.sessionGeneration
        biometricUnlockAuthorization = null
        if (!prefs.biometricEnabledFlow.first()) return null
        val blobB64 = prefs.biometricWrappedDek() ?: return null
        if (!KeystoreManager.hasKey()) return null
        val blob = CryptoManager.decode(blobB64)
        val (iv, ciphertext) = try {
            KeystoreManager.splitIv(blob)
        } finally {
            blob.fill(0)
        }
        return try {
            val cipher = KeystoreManager.decryptCipher(iv)
            if (generation != SessionManager.sessionGeneration) {
                throw VaultLockedException("Authentication session expired")
            }
            biometricUnlockAuthorization = BiometricAuthorization(cipher, generation, blobB64)
            cipher
        } catch (e: VaultLockedException) {
            throw e
        } catch (_: Exception) {
            null
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    /** Completes biometric unlock using the authenticated decrypt cipher. */
    suspend fun unlockWithBiometricCipher(authenticatedCipher: Cipher): UnlockResult =
        credentialOperation { unlockWithBiometricCipherInternal(authenticatedCipher) }

    private suspend fun unlockWithBiometricCipherInternal(authenticatedCipher: Cipher): UnlockResult {
        val authorization = biometricUnlockAuthorization
        biometricUnlockAuthorization = null
        if (authorization == null || authorization.cipher !== authenticatedCipher ||
            authorization.sessionGeneration != SessionManager.sessionGeneration ||
            !prefs.biometricEnabledFlow.first()
        ) return UnlockResult.Error("指纹验证已失效，请重新验证")
        val generation = authorization.sessionGeneration
        val blobB64 = prefs.biometricWrappedDek() ?: return UnlockResult.Error("尚未启用指纹解锁")
        if (blobB64 != authorization.wrappedDek) return UnlockResult.Error("指纹验证已失效，请重新验证")
        return try {
            val blob = CryptoManager.decode(blobB64)
            val (iv, ciphertext) = try {
                KeystoreManager.splitIv(blob)
            } finally {
                blob.fill(0)
            }
            try {
                val dekBytes = authenticatedCipher.doFinal(ciphertext)
                val dek = secretKeyFromBytes(dekBytes)
                var transferred = false
                try {
                    prefs.resetFailures()
                    SessionManager.unlock(dek, generation)
                    transferred = true
                    UnlockResult.Success
                } finally {
                    if (!transferred) CryptoManager.destroyKey(dek)
                }
            } finally {
                iv.fill(0)
                ciphertext.fill(0)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            UnlockResult.Error("指纹解锁失败")
        }
    }

    /**
     * Migrates the short-lived v1 device-protection envelope used by an earlier release.
     *
     * The outer Android Keystore key was not biometric-bound, so making the password-derived
     * recovery envelopes depend on it made a Keystore reset unrecoverable even with the correct
     * master password. The DEK remains AES-GCM encrypted under the master/mnemonic KDF
     * keys; only that redundant outer envelope is removed. Call after a successful unlock while
     * the legacy Keystore key is still available.
     */
    suspend fun migrateLegacyDeviceWrappedMaterial() = credentialOperation {
        masterWrappedDekBytes()?.fill(0)
        if (!prefs.mnemonicWrappedDek().isNullOrBlank()) {
            mnemonicWrappedDekBytes()?.fill(0)
        }
        if (!prefs.mnemonicVerifierHash().isNullOrBlank()) {
            mnemonicVerifierHash()
        }
        // The retired alias is intentionally left available for short-lived pending Autofill
        // captures. It no longer protects any long-lived recovery material and can be removed
        // safely as part of an explicit full reset.
    }

    private fun wrapDek(wrappingKey: SecretKey, dek: SecretKey): ByteArray {
        val dekBytes = dek.encoded
        return try {
            CryptoManager.encrypt(wrappingKey, dekBytes)
        } finally {
            dekBytes.fill(0)
        }
    }

    private fun encodeWrappedDek(wrappedDek: ByteArray): String {
        // The wrapping key is already derived from a user secret with PBKDF2 and the ciphertext
        // is authenticated by AES-GCM. Do not add a non-biometric device-key dependency here:
        // an Android Keystore reset must not make a vault unrecoverable with its master password.
        return CryptoManager.encode(wrappedDek)
    }

    private suspend fun masterWrappedDekBytes(): ByteArray? {
        val stored = prefs.masterWrappedDek()
        return decodeStoredWrappedDek(stored) {
            prefs.updateMasterWrappedDekIfUnchanged(stored.orEmpty(), it)
        }
    }

    private suspend fun mnemonicWrappedDekBytes(migrate: Boolean = true): ByteArray? {
        val stored = prefs.mnemonicWrappedDek()
        return decodeStoredWrappedDek(stored) {
            if (migrate) prefs.updateMnemonicWrappedDekIfUnchanged(stored.orEmpty(), it)
        }
    }

    private suspend fun mnemonicVerifierHash(migrate: Boolean = true): String? {
        val stored = prefs.mnemonicVerifierHash()
        return decodeProtectedString(stored) {
            if (migrate) prefs.updateMnemonicVerifierHashIfUnchanged(stored.orEmpty(), it)
        }
    }

    private suspend fun decodeStoredWrappedDek(
        stored: String?,
        persistMigrated: suspend (String) -> Unit
    ): ByteArray? {
        if (stored.isNullOrBlank()) return null
        return if (stored.startsWith(DEVICE_WRAPPED_PREFIX)) {
            val blob = CryptoManager.decode(stored.removePrefix(DEVICE_WRAPPED_PREFIX))
            try {
                val migrated = KeystoreManager.unwrapWithDeviceKey(blob)
                try {
                    persistMigrated(CryptoManager.encode(migrated))
                    migrated
                } catch (e: Exception) {
                    migrated.fill(0)
                    throw e
                }
            } finally {
                blob.fill(0)
            }
        } else {
            CryptoManager.decode(stored)
        }
    }

    private suspend fun decodeProtectedString(
        stored: String?,
        persistMigrated: suspend (String) -> Unit
    ): String? {
        if (stored.isNullOrBlank()) return null
        return if (stored.startsWith(DEVICE_WRAPPED_PREFIX)) {
            val blob = CryptoManager.decode(stored.removePrefix(DEVICE_WRAPPED_PREFIX))
            val bytes = try {
                KeystoreManager.unwrapWithDeviceKey(blob)
            } finally {
                blob.fill(0)
            }
            try {
                val migrated = String(bytes, Charsets.UTF_8)
                persistMigrated(migrated)
                migrated
            } finally {
                bytes.fill(0)
            }
        } else {
            stored
        }
    }

    private fun secretKeyFromBytes(bytes: ByteArray): SecretKey =
        try {
            CryptoManager.keyFromBytes(bytes)
        } finally {
            bytes.fill(0)
        }

    private suspend fun masterKdfSpec(): KdfSpec =
        KdfVersions.stored(prefs.masterKdfVersion(), prefs.masterIterations())

    private suspend fun mnemonicKdfSpec(): KdfSpec =
        KdfVersions.stored(prefs.mnemonicKdfVersion(), prefs.mnemonicIterations())

}
