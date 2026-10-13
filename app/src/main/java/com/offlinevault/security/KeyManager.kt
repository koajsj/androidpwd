package com.offlinevault.security

import com.offlinevault.data.preferences.SecurityPreferences
import kotlinx.coroutines.CancellationException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import java.util.Locale

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
 *                          └─ wrapped by ──▶ recovery key = PBKDF2(recoveryAnswer, recoverySalt)
 * The DEK is never stored in the clear. Master password and recovery answer are never stored at all.
 */
class KeyManager(
    private val prefs: SecurityPreferences,
    private val mnemonicManager: MnemonicManager
) {
    companion object {
        private const val DEVICE_WRAPPED_PREFIX = "ks:v1:"
        private const val MNEMONIC_REAUTH_WINDOW_MILLIS = 5 * 60 * 1_000L
        const val MIN_NEW_RECOVERY_ANSWER_LENGTH = 4
    }

    private data class MnemonicUpdateAuthorization(
        val sessionGeneration: Long,
        val expiresAtMillis: Long
    )

    /** In-memory, single-use proof of a recent master-password reauthentication. */
    private var mnemonicUpdateAuthorization: MnemonicUpdateAuthorization? = null

    /** First launch: create the DEK and wrap it under both the master password and recovery answer. */
    suspend fun setup(
        masterPassword: String,
        recoveryQuestion: String,
        recoveryAnswer: String,
        mnemonicPhrase: String
    ) {
        val generation = SessionManager.sessionGeneration
        require(masterPassword.isNotBlank()) { "主密码不能为空" }
        require(recoveryQuestion.isNotBlank()) { "安全问题不能为空" }
        require(recoveryAnswer.trim().length >= MIN_NEW_RECOVERY_ANSWER_LENGTH) {
            "安全问题答案至少需要 $MIN_NEW_RECOVERY_ANSWER_LENGTH 个字符"
        }
        val normalizedMnemonic = mnemonicManager.normalize(mnemonicPhrase)
        require(mnemonicManager.isValidPhrase(normalizedMnemonic)) { "助记词格式无效" }
        val dek = CryptoManager.newDataEncryptionKey()

        val masterSalt = CryptoManager.newSalt()
        val recoverySalt = CryptoManager.newSalt()
        val mnemonicSalt = CryptoManager.newSalt()
        var masterWrapped = ByteArray(0)
        var recoveryWrapped = ByteArray(0)
        var mnemonicWrapped = ByteArray(0)
        var dekTransferredToSession = false
        try {
            val kdf = KdfVersions.current()
            val mnemonicKdf = KdfVersions.current()
            masterWrapped = wrapDekWithSecret(masterPassword, masterSalt, kdf, dek)
            recoveryWrapped = wrapDekWithSecret(
                normalizeAnswer(recoveryAnswer),
                recoverySalt,
                kdf,
                dek
            )
            val mnemonicKey = mnemonicManager.deriveRecoveryKey(
                normalizedMnemonic,
                mnemonicSalt,
                mnemonicKdf
            )
            mnemonicWrapped = try {
                wrapDek(mnemonicKey, dek)
            } finally {
                CryptoManager.destroyKey(mnemonicKey)
            }
            val mnemonicVerifierHash =
                mnemonicManager.verifierHash(normalizedMnemonic, mnemonicSalt, mnemonicKdf)
            prefs.saveVaultMaterial(
                masterSalt = CryptoManager.encode(masterSalt),
                recoverySalt = CryptoManager.encode(recoverySalt),
                masterWrappedDek = encodeWrappedDek(masterWrapped),
                recoveryWrappedDek = encodeWrappedDek(recoveryWrapped),
                recoveryQuestion = recoveryQuestion,
                masterIterations = kdf.iterations,
                recoveryIterations = kdf.iterations,
                masterKdfVersion = kdf.version,
                recoveryKdfVersion = kdf.version,
                mnemonicSalt = CryptoManager.encode(mnemonicSalt),
                mnemonicWrappedDek = encodeWrappedDek(mnemonicWrapped),
                mnemonicVerifierHash = encodeProtectedString(mnemonicVerifierHash),
                mnemonicIterations = mnemonicKdf.iterations,
                mnemonicKdfVersion = mnemonicKdf.version
            )
            prefs.resetFailures()
            SessionManager.unlock(dek, generation)
            dekTransferredToSession = true
        } finally {
            masterSalt.fill(0)
            recoverySalt.fill(0)
            mnemonicSalt.fill(0)
            masterWrapped.fill(0)
            recoveryWrapped.fill(0)
            mnemonicWrapped.fill(0)
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

    suspend fun unlockWithPassword(masterPassword: String): UnlockResult {
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

    /** Recovery: answer the security question, recover the DEK, then set a brand new master password. */
    suspend fun recoverWithAnswer(recoveryAnswer: String, newMasterPassword: String): UnlockResult {
        if (newMasterPassword.isBlank()) return UnlockResult.Error("新主密码不能为空")
        val delay = unlockDelaySeconds()
        if (delay > 0) return UnlockResult.Delayed(delay)

        val saltB64 = prefs.recoverySalt() ?: return UnlockResult.Error("未设置恢复信息")
        val wrappedDek = recoveryWrappedDekBytes() ?: return UnlockResult.Error("未设置恢复信息")

        val dekBytes = try {
            decryptWithRecoveryAnswer(recoveryAnswer, saltB64, wrappedDek)
        } catch (e: CancellationException) {
            throw e
        } catch (_: AEADBadTagException) {
            prefs.recordFailure()
            return UnlockResult.WrongCredential
        } catch (_: Exception) {
            return UnlockResult.Error("无法读取恢复密钥，数据可能已损坏")
        } finally {
            wrappedDek.fill(0)
        }

        // Re-wrap the recovered DEK under a fresh master password.
        val dek = secretKeyFromBytes(dekBytes)
        return try {
            rewrapMaster(dek, newMasterPassword, resetFailures = true)
            // Recovery is never an unlock mechanism. The normal UI calls this while locked, but
            // enforce that invariant here as well so a future caller cannot keep an old session
            // alive after replacing the master credential.
            SessionManager.lock()
            UnlockResult.Success
        } finally {
            CryptoManager.destroyKey(dek)
        }
    }

    /** Final recovery path: 12-word phrase recovers the DEK and only resets the master password. */
    suspend fun recoverWithMnemonic(mnemonicPhrase: String, newMasterPassword: String): UnlockResult {
        if (newMasterPassword.isBlank()) return UnlockResult.Error("新主密码不能为空")
        val delay = unlockDelaySeconds()
        if (delay > 0) return UnlockResult.Delayed(delay)

        val saltB64 = prefs.mnemonicSalt() ?: return UnlockResult.Error("未启用助记词恢复")
        val wrappedDek = mnemonicWrappedDekBytes() ?: return UnlockResult.Error("未启用助记词恢复")
        try {
            val verifierHash = mnemonicVerifierHash() ?: return UnlockResult.Error("未启用助记词恢复")
            val normalizedMnemonic = mnemonicManager.normalize(mnemonicPhrase)
            if (!mnemonicManager.isValidPhrase(normalizedMnemonic)) {
                prefs.recordFailure()
                return UnlockResult.WrongCredential
            }

            val dekBytes = try {
                val salt = CryptoManager.decode(saltB64)
                val mnemonicKdf = mnemonicKdfSpec()
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
                rewrapMaster(dek, newMasterPassword, resetFailures = true)
                // A valid recovery phrase may reset the master credential only; it must not
                // become a second, implicit daily-unlock path.
                SessionManager.lock()
                UnlockResult.Success
            } finally {
                CryptoManager.destroyKey(dek)
            }
        } finally {
            wrappedDek.fill(0)
        }
    }

    /** Change master password: verify the old one, then re-wrap the DEK under the new one. */
    suspend fun changeMasterPassword(oldPassword: String, newPassword: String): UnlockResult {
        if (newPassword.isBlank()) return UnlockResult.Error("新主密码不能为空")
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
            rewrapMaster(dek, newPassword, resetFailures = true)
            UnlockResult.Success
        } finally {
            CryptoManager.destroyKey(dek)
        }
    }

    /** Verifies the current master credential without unlocking or exposing the DEK to callers. */
    suspend fun verifyMasterCredential(masterPassword: String): UnlockResult {
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

    /** Replace the security question / answer. Requires the vault to be currently unlocked. */
    suspend fun changeRecovery(question: String, answer: String) {
        require(question.isNotBlank()) { "安全问题不能为空" }
        require(answer.trim().length >= MIN_NEW_RECOVERY_ANSWER_LENGTH) {
            "安全问题答案至少需要 $MIN_NEW_RECOVERY_ANSWER_LENGTH 个字符"
        }
        SessionManager.withActiveSession {
            val salt = CryptoManager.newSalt()
            try {
                val kdf = KdfVersions.current()
                val wrapped = wrapDekWithSecret(normalizeAnswer(answer), salt, kdf, SessionManager.requireKey())
                try {
                    prefs.updateRecoveryMaterial(
                        recoverySalt = CryptoManager.encode(salt),
                        recoveryWrappedDek = encodeWrappedDek(wrapped),
                        recoveryQuestion = question,
                        recoveryIterations = kdf.iterations,
                        recoveryKdfVersion = kdf.version
                    )
                } finally {
                    wrapped.fill(0)
                }
            } finally {
                salt.fill(0)
            }
        }
    }

    /** Creates an in-memory, short-lived and single-use authorization for a mnemonic update. */
    suspend fun authorizeMnemonicRecoveryUpdate(masterPassword: String): UnlockResult {
        if (!SessionManager.isUnlocked) return UnlockResult.Error("密码库已锁定，请重新解锁")
        val result = verifyMasterCredential(masterPassword)
        synchronized(this) {
            mnemonicUpdateAuthorization = if (result is UnlockResult.Success && SessionManager.isUnlocked) {
                MnemonicUpdateAuthorization(
                    sessionGeneration = SessionManager.sessionGeneration,
                    expiresAtMillis = System.currentTimeMillis() + MNEMONIC_REAUTH_WINDOW_MILLIS
                )
            } else {
                null
            }
        }
        return result
    }

    /** Consumes the recent master-password authorization before replacing mnemonic material. */
    suspend fun updateMnemonicRecoveryForUnlockedSession(mnemonicPhrase: String): UnlockResult {
        val authorization = synchronized(this) {
            mnemonicUpdateAuthorization.also { mnemonicUpdateAuthorization = null }
        }
        if (authorization == null ||
            authorization.expiresAtMillis < System.currentTimeMillis() ||
            authorization.sessionGeneration != SessionManager.sessionGeneration ||
            !SessionManager.isUnlocked
        ) {
            return UnlockResult.Error("请先验证当前主密码")
        }
        return try {
            SessionManager.withActiveSession {
                SessionManager.requireActiveSession(authorization.sessionGeneration)
                updateMnemonicRecoveryForDek(SessionManager.requireKey(), mnemonicPhrase)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            UnlockResult.Error("密码库已锁定，请重新解锁")
        }
    }

    private suspend fun updateMnemonicRecoveryForDek(
        dek: SecretKey,
        mnemonicPhrase: String
    ): UnlockResult {
        val normalizedMnemonic = mnemonicManager.normalize(mnemonicPhrase)
        if (!mnemonicManager.isValidPhrase(normalizedMnemonic)) return UnlockResult.Error("助记词格式无效")

        val salt = CryptoManager.newSalt()
        try {
            val mnemonicKdf = KdfVersions.current()
            val mnemonicKey = mnemonicManager.deriveRecoveryKey(normalizedMnemonic, salt, mnemonicKdf)
            val wrapped = try {
                wrapDek(mnemonicKey, dek)
            } finally {
                CryptoManager.destroyKey(mnemonicKey)
            }
            try {
                prefs.updateMnemonicMaterial(
                    mnemonicSalt = CryptoManager.encode(salt),
                    mnemonicWrappedDek = encodeWrappedDek(wrapped),
                    mnemonicVerifierHash = encodeProtectedString(mnemonicManager.verifierHash(normalizedMnemonic, salt, mnemonicKdf)),
                    mnemonicIterations = mnemonicKdf.iterations,
                    mnemonicKdfVersion = mnemonicKdf.version
                )
            } finally {
                wrapped.fill(0)
            }
        } finally {
            salt.fill(0)
        }
        prefs.resetFailures()
        return UnlockResult.Success
    }

    suspend fun disableMnemonicRecovery(masterPassword: String): UnlockResult {
        val delay = unlockDelaySeconds()
        if (delay > 0) return UnlockResult.Delayed(delay)

        // Disabling only needs proof of the current master credential. Avoid materialising a
        // second DEK object solely for this confirmation action.
        when (val verification = verifyMasterCredential(masterPassword)) {
            is UnlockResult.Success -> Unit
            else -> return verification
        }
        prefs.clearMnemonicMaterial()
        return UnlockResult.Success
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

    /**
     * Uses a locale-independent recovery-answer representation for new vaults. Earlier releases
     * used the device default locale, so a one-time fallback keeps an existing Turkish-locale
     * vault recoverable without weakening the canonical form going forward.
     */
    private suspend fun decryptWithRecoveryAnswer(
        recoveryAnswer: String,
        saltB64: String,
        wrappedDek: ByteArray
    ): ByteArray {
        val salt = CryptoManager.decode(saltB64)
        val kdf = recoveryKdfSpec()
        val canonical = normalizeAnswer(recoveryAnswer)
        try {
            return decryptWithRecoveryAnswerForm(canonical, salt, kdf, wrappedDek)
        } catch (first: AEADBadTagException) {
            val legacy = normalizeLegacyAnswer(recoveryAnswer)
            if (legacy == canonical) throw first
            return decryptWithRecoveryAnswerForm(legacy, salt, kdf, wrappedDek)
        } finally {
            salt.fill(0)
        }
    }

    private fun decryptWithRecoveryAnswerForm(
        answer: String,
        salt: ByteArray,
        kdf: KdfSpec,
        wrappedDek: ByteArray
    ): ByteArray {
        return decryptWithSecret(answer, salt, kdf, wrappedDek)
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

    /**
     * Persists the DEK wrapped by the biometric-bound Keystore key.
     * [authenticatedCipher] must already have passed through BiometricPrompt in ENCRYPT mode.
     */
    suspend fun storeBiometricWrappedDek(authenticatedCipher: Cipher) {
        SessionManager.withActiveSession {
            val dekBytes = SessionManager.requireKey().encoded
            val ciphertext = try {
                authenticatedCipher.doFinal(dekBytes)
            } finally {
                dekBytes.fill(0)
            }
            val iv = authenticatedCipher.iv
            val blob = KeystoreManager.joinIv(iv, ciphertext)
            try {
                prefs.setBiometric(enabled = true, wrappedDek = CryptoManager.encode(blob))
            } finally {
                iv.fill(0)
                ciphertext.fill(0)
                blob.fill(0)
            }
        }
    }

    suspend fun disableBiometric() {
        prefs.setBiometric(enabled = false, wrappedDek = null)
        KeystoreManager.deleteBiometricKey()
    }

    /** Builds a decrypt cipher (gated by biometrics) for the stored wrapped DEK, or null if unavailable. */
    suspend fun biometricDecryptCipher(): Cipher? {
        val blobB64 = prefs.biometricWrappedDek() ?: return null
        if (!KeystoreManager.hasKey()) return null
        val blob = CryptoManager.decode(blobB64)
        val (iv, ciphertext) = try {
            KeystoreManager.splitIv(blob)
        } finally {
            blob.fill(0)
        }
        return try {
            KeystoreManager.decryptCipher(iv)
        } catch (_: Exception) {
            null
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    /** Completes biometric unlock using the authenticated decrypt cipher. */
    suspend fun unlockWithBiometricCipher(authenticatedCipher: Cipher): UnlockResult {
        val generation = SessionManager.sessionGeneration
        val blobB64 = prefs.biometricWrappedDek() ?: return UnlockResult.Error("尚未启用指纹解锁")
        return try {
            val blob = CryptoManager.decode(blobB64)
            val (_, ciphertext) = try {
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
     * master password. The DEK remains AES-GCM encrypted under the master/recovery/mnemonic KDF
     * keys; only that redundant outer envelope is removed. Call after a successful unlock while
     * the legacy Keystore key is still available.
     */
    suspend fun migrateLegacyDeviceWrappedMaterial() {
        masterWrappedDekBytes()?.fill(0)
        recoveryWrappedDekBytes()?.fill(0)
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

    private suspend fun recoveryWrappedDekBytes(): ByteArray? {
        val stored = prefs.recoveryWrappedDek()
        return decodeStoredWrappedDek(stored) {
            prefs.updateRecoveryWrappedDekIfUnchanged(stored.orEmpty(), it)
        }
    }

    private suspend fun mnemonicWrappedDekBytes(): ByteArray? {
        val stored = prefs.mnemonicWrappedDek()
        return decodeStoredWrappedDek(stored) {
            prefs.updateMnemonicWrappedDekIfUnchanged(stored.orEmpty(), it)
        }
    }

    private suspend fun mnemonicVerifierHash(): String? {
        val stored = prefs.mnemonicVerifierHash()
        return decodeProtectedString(stored) {
            prefs.updateMnemonicVerifierHashIfUnchanged(stored.orEmpty(), it)
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

    private fun encodeProtectedString(value: String): String {
        // This is a verifier, not a plaintext credential. Keeping it portable preserves mnemonic
        // recovery after a non-biometric Android Keystore reset.
        return value
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

    private suspend fun recoveryKdfSpec(): KdfSpec =
        KdfVersions.stored(prefs.recoveryKdfVersion(), prefs.recoveryIterations())

    private suspend fun mnemonicKdfSpec(): KdfSpec =
        KdfVersions.stored(prefs.mnemonicKdfVersion(), prefs.mnemonicIterations())

    /** Normalises recovery answers so capitalisation / surrounding spaces don't matter. */
    private fun normalizeAnswer(answer: String): String = answer.trim().lowercase(Locale.ROOT)

    /** Compatibility form used only after the stable form fails to unlock legacy material. */
    private fun normalizeLegacyAnswer(answer: String): String = answer.trim().lowercase()
}
