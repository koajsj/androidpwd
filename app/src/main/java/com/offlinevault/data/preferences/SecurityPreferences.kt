package com.offlinevault.data.preferences

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.SessionManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

// NEVER rename this store: it holds the salts and wrapped DEKs. Renaming orphans every vault and
// effectively destroys the user's data. Add new keys instead; old keys may be absent on upgrade,
// so every accessor must default safely for vaults created by earlier versions.
private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "offline_vault_secure_prefs")

/** App level (non-secret-bearing key material + user settings) persistence backed by DataStore. */
class SecurityPreferences(private val context: Context) {

    /** Ciphertext and public derivation parameters only; never a phrase or plaintext key. */
    data class MnemonicMaterial(
        val salt: String,
        val wrappedDek: String,
        val verifierHash: String,
        val iterations: Int,
        val kdfVersion: String
    )

    companion object {
        private const val DEFAULT_AUTO_LOCK_SECONDS = 60
        private const val MIN_AUTO_LOCK_SECONDS = 0
        private const val MAX_AUTO_LOCK_SECONDS = 60 * 60

        private const val DEFAULT_CLIPBOARD_CLEAR_SECONDS = 10
        private const val MIN_CLIPBOARD_CLEAR_SECONDS = 5
        private const val MAX_CLIPBOARD_CLEAR_SECONDS = 60
    }

    private object Keys {
        val MASTER_SALT = stringPreferencesKey("master_salt")
        val RECOVERY_SALT = stringPreferencesKey("recovery_salt")
        val MASTER_WRAPPED_DEK = stringPreferencesKey("master_wrapped_dek")
        val RECOVERY_WRAPPED_DEK = stringPreferencesKey("recovery_wrapped_dek")
        val RECOVERY_QUESTION = stringPreferencesKey("recovery_question")
        val MNEMONIC_SALT = stringPreferencesKey("mnemonic_salt")
        val MNEMONIC_WRAPPED_DEK = stringPreferencesKey("mnemonic_wrapped_dek")
        val MNEMONIC_VERIFIER_HASH = stringPreferencesKey("mnemonic_verifier_hash")
        val MNEMONIC_ITERATIONS = intPreferencesKey("mnemonic_iterations")
        val MNEMONIC_KDF_VERSION = stringPreferencesKey("mnemonic_kdf_version")

        // PBKDF2 iteration counts the master / recovery keys were derived with. Persisted so the
        // default can be raised over time without locking existing vaults out. Absent => legacy.
        val MASTER_ITERATIONS = intPreferencesKey("master_iterations")
        val RECOVERY_ITERATIONS = intPreferencesKey("recovery_iterations")
        val MASTER_KDF_VERSION = stringPreferencesKey("master_kdf_version")
        val RECOVERY_KDF_VERSION = stringPreferencesKey("recovery_kdf_version")

        val CREDENTIAL_TYPE = stringPreferencesKey("credential_type")

        val BIOMETRIC_ENABLED = booleanPreferencesKey("biometric_enabled")
        val BIOMETRIC_WRAPPED_DEK = stringPreferencesKey("biometric_wrapped_dek")

        val AUTO_LOCK_MINUTES = intPreferencesKey("auto_lock_minutes")
        val AUTO_LOCK_SECONDS = intPreferencesKey("auto_lock_seconds")
        val LOCK_ON_SCREEN_OFF = booleanPreferencesKey("lock_on_screen_off")
        val SCREENSHOT_BLOCKED = booleanPreferencesKey("screenshot_blocked")
        val CLIPBOARD_CLEAR_SECONDS = intPreferencesKey("clipboard_clear_seconds")
        val AUTOFILL_BANNER_DISMISSED = booleanPreferencesKey("autofill_banner_dismissed")
        val HEALTH_CHECK_ENABLED = booleanPreferencesKey("health_check_enabled")
        val LAST_BACKUP_WRITTEN_AT = longPreferencesKey("last_backup_written_at")

        val FAILED_ATTEMPTS = intPreferencesKey("failed_attempts")
        val LAST_FAILED_AT = longPreferencesKey("last_failed_at")
        // Local risk-engine state. No device ID, credential, or user behavior leaves this app.
        val DEVICE_TRUSTED = booleanPreferencesKey("device_trusted")
        val UNLOCK_WINDOW_STARTED_AT = longPreferencesKey("unlock_window_started_at")
        val SUCCESSFUL_UNLOCKS_IN_WINDOW = intPreferencesKey("successful_unlocks_in_window")
    }

    // ---- Security material -------------------------------------------------

    val lastBackupWrittenAtFlow: Flow<Long?> = context.dataStore.data
        .map<Preferences, Long?> { it[Keys.LAST_BACKUP_WRITTEN_AT] ?: 0L }.catch { emit(null) }

    suspend fun recordBackupWritten() {
        context.dataStore.edit { it[Keys.LAST_BACKUP_WRITTEN_AT] = System.currentTimeMillis() }
    }

    val initializedFlow: Flow<Boolean> =
        context.dataStore.data
            .map { it[Keys.MASTER_WRAPPED_DEK] != null }
            // Fail closed: a preferences read error must not expose setup over an existing vault.
            .catch { emit(true) }

    suspend fun saveVaultMaterial(
        masterSalt: String,
        masterWrappedDek: String,
        masterIterations: Int,
        masterKdfVersion: String,
        mnemonic: MnemonicMaterial,
        credentialType: String
    ) {
        context.dataStore.edit {
            check(it[Keys.MASTER_WRAPPED_DEK] == null) { "Vault is already initialized" }
            it[Keys.MASTER_SALT] = masterSalt
            it[Keys.MASTER_WRAPPED_DEK] = masterWrappedDek
            it[Keys.MASTER_ITERATIONS] = masterIterations
            it[Keys.MASTER_KDF_VERSION] = masterKdfVersion
            it.setMnemonic(mnemonic)
            it[Keys.CREDENTIAL_TYPE] = credentialType
            it[Keys.FAILED_ATTEMPTS] = 0
            it[Keys.LAST_FAILED_AT] = 0L
        }
    }

    suspend fun updateMasterMaterial(
        masterSalt: String,
        masterWrappedDek: String,
        masterIterations: Int,
        masterKdfVersion: String
    ) {
        context.dataStore.edit {
            it[Keys.MASTER_SALT] = masterSalt
            it[Keys.MASTER_WRAPPED_DEK] = masterWrappedDek
            it[Keys.MASTER_ITERATIONS] = masterIterations
            it[Keys.MASTER_KDF_VERSION] = masterKdfVersion
        }
    }

    /** Replaces master wrapping material and clears the recovery throttle in one DataStore edit. */
    suspend fun updateMasterMaterialAndResetFailures(
        masterSalt: String,
        masterWrappedDek: String,
        masterIterations: Int,
        masterKdfVersion: String
    ) {
        context.dataStore.edit {
            it[Keys.MASTER_SALT] = masterSalt
            it[Keys.MASTER_WRAPPED_DEK] = masterWrappedDek
            it[Keys.MASTER_ITERATIONS] = masterIterations
            it[Keys.MASTER_KDF_VERSION] = masterKdfVersion
            it[Keys.FAILED_ATTEMPTS] = 0
            it[Keys.LAST_FAILED_AT] = 0L
        }
    }

    suspend fun updateMasterWrappedDekIfUnchanged(expected: String, replacement: String) {
        context.dataStore.edit {
            if (it[Keys.MASTER_WRAPPED_DEK] == expected) {
                it[Keys.MASTER_WRAPPED_DEK] = replacement
            }
        }
    }

    /** Recovery replaces all required envelopes, retires the answer and resets failures atomically. */
    suspend fun completeRecovery(
        masterSalt: String,
        masterWrappedDek: String,
        masterIterations: Int,
        masterKdfVersion: String,
        expectedGeneration: Long,
        mnemonic: MnemonicMaterial
    ) {
        context.dataStore.edit {
            SessionManager.withRecoveryCommit(expectedGeneration) {
                it[Keys.MASTER_SALT] = masterSalt
                it[Keys.MASTER_WRAPPED_DEK] = masterWrappedDek
                it[Keys.MASTER_ITERATIONS] = masterIterations
                it[Keys.MASTER_KDF_VERSION] = masterKdfVersion
                it.setMnemonic(mnemonic)
                it.retireLegacyAnswer()
                it[Keys.FAILED_ATTEMPTS] = 0
                it[Keys.LAST_FAILED_AT] = 0L
            }
        }
    }

    private fun MutablePreferences.setMnemonic(material: MnemonicMaterial) {
        this[Keys.MNEMONIC_SALT] = material.salt
        this[Keys.MNEMONIC_WRAPPED_DEK] = material.wrappedDek
        this[Keys.MNEMONIC_VERIFIER_HASH] = material.verifierHash
        this[Keys.MNEMONIC_ITERATIONS] = material.iterations
        this[Keys.MNEMONIC_KDF_VERSION] = material.kdfVersion
    }

    private fun MutablePreferences.retireLegacyAnswer() {
        remove(Keys.RECOVERY_SALT)
        remove(Keys.RECOVERY_WRAPPED_DEK)
        remove(Keys.RECOVERY_QUESTION)
        remove(Keys.RECOVERY_ITERATIONS)
        remove(Keys.RECOVERY_KDF_VERSION)
    }

    suspend fun masterSalt(): String? = context.dataStore.data.first()[Keys.MASTER_SALT]
    suspend fun masterWrappedDek(): String? = context.dataStore.data.first()[Keys.MASTER_WRAPPED_DEK]
    suspend fun mnemonicSalt(): String? = context.dataStore.data.first()[Keys.MNEMONIC_SALT]
    suspend fun mnemonicWrappedDek(): String? = context.dataStore.data.first()[Keys.MNEMONIC_WRAPPED_DEK]
    suspend fun mnemonicVerifierHash(): String? = context.dataStore.data.first()[Keys.MNEMONIC_VERIFIER_HASH]

    /** Iteration counts; absent material predates persistence and uses the legacy count. */
    suspend fun masterIterations(): Int =
        context.dataStore.data.first()[Keys.MASTER_ITERATIONS] ?: CryptoManager.LEGACY_PBKDF2_ITERATIONS

    suspend fun masterKdfVersion(): String? = context.dataStore.data.first()[Keys.MASTER_KDF_VERSION]
    // Existing mnemonic material was created with the then-current PBKDF2 default (300k).
    suspend fun mnemonicIterations(): Int =
        context.dataStore.data.first()[Keys.MNEMONIC_ITERATIONS] ?: CryptoManager.DEFAULT_PBKDF2_ITERATIONS
    suspend fun mnemonicKdfVersion(): String? = context.dataStore.data.first()[Keys.MNEMONIC_KDF_VERSION]

    // Legacy compatibility: vaults created before the credential type existed were password-only.
    // If no type was stored but a vault already exists, treat it as a password so the unlock screen
    // shows the full keyboard — defaulting such users to a numeric PIN would lock them out. Only a
    // fresh install (no vault material) gets the new PIN6 default. On read error fall back to the
    // least-restrictive password keyboard.
    val credentialTypeFlow: Flow<String> =
        context.dataStore.data.map { prefs ->
            prefs[Keys.CREDENTIAL_TYPE]
                ?: if (prefs[Keys.MASTER_WRAPPED_DEK] != null) "password" else "pin6"
        }.catch { emit("password") }

    /** null means unreadable, not proof that weak legacy material is absent. */
    val legacyAnswerPendingFlow: Flow<Boolean?> = context.dataStore.data
        .map<Preferences, Boolean?> { it[Keys.RECOVERY_WRAPPED_DEK] != null }
        .catch { emit(null) }

    val mnemonicEnabledFlow: Flow<Boolean> =
        context.dataStore.data
            .map {
                !it[Keys.MNEMONIC_SALT].isNullOrBlank() &&
                    !it[Keys.MNEMONIC_WRAPPED_DEK].isNullOrBlank() &&
                    !it[Keys.MNEMONIC_VERIFIER_HASH].isNullOrBlank()
            }
            .catch { emit(false) }

    suspend fun updateMnemonicMaterial(
        material: MnemonicMaterial,
        expectedGeneration: Long
    ) {
        context.dataStore.edit {
            SessionManager.withActiveSessionNow(expectedGeneration) {
                it.setMnemonic(material)
                it.retireLegacyAnswer()
                it[Keys.FAILED_ATTEMPTS] = 0
                it[Keys.LAST_FAILED_AT] = 0L
            }
        }
    }

    suspend fun updateMnemonicWrappedDekIfUnchanged(expected: String, replacement: String) {
        context.dataStore.edit {
            if (it[Keys.MNEMONIC_WRAPPED_DEK] == expected) {
                it[Keys.MNEMONIC_WRAPPED_DEK] = replacement
            }
        }
    }

    suspend fun updateMnemonicVerifierHashIfUnchanged(expected: String, replacement: String) {
        context.dataStore.edit {
            if (it[Keys.MNEMONIC_VERIFIER_HASH] == expected) {
                it[Keys.MNEMONIC_VERIFIER_HASH] = replacement
            }
        }
    }

    suspend fun clearMnemonicMaterial(expectedGeneration: Long) {
        context.dataStore.edit {
            SessionManager.withActiveSessionNow(expectedGeneration) {
                it.remove(Keys.MNEMONIC_SALT)
                it.remove(Keys.MNEMONIC_WRAPPED_DEK)
                it.remove(Keys.MNEMONIC_VERIFIER_HASH)
                it.remove(Keys.MNEMONIC_ITERATIONS)
                it.remove(Keys.MNEMONIC_KDF_VERSION)
            }
        }
    }

    // ---- Biometric ---------------------------------------------------------

    val biometricEnabledFlow: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.BIOMETRIC_ENABLED] ?: false }.catch { emit(false) }

    suspend fun setBiometric(enabled: Boolean, wrappedDek: String?, expectedGeneration: Long? = null) {
        context.dataStore.edit {
            if (enabled) {
                SessionManager.withActiveSessionNow(requireNotNull(expectedGeneration)) {
                    it[Keys.BIOMETRIC_ENABLED] = true
                    it[Keys.BIOMETRIC_WRAPPED_DEK] = requireNotNull(wrappedDek)
                }
            } else {
                it[Keys.BIOMETRIC_ENABLED] = false
                it.remove(Keys.BIOMETRIC_WRAPPED_DEK)
            }
        }
    }

    suspend fun biometricWrappedDek(): String? =
        context.dataStore.data.first()[Keys.BIOMETRIC_WRAPPED_DEK]

    // ---- User settings -----------------------------------------------------

    // Auto-lock delay in SECONDS. Older installs stored whole minutes under AUTO_LOCK_MINUTES; when the
    // new key is absent we fall back to that value (× 60) so existing users keep their setting.
    private fun Preferences.autoLockSeconds(): Int =
        (this[Keys.AUTO_LOCK_SECONDS] ?: ((this[Keys.AUTO_LOCK_MINUTES] ?: 1) * 60))
            .coerceIn(MIN_AUTO_LOCK_SECONDS, MAX_AUTO_LOCK_SECONDS)

    val autoLockSecondsFlow: Flow<Int> =
        context.dataStore.data.map { it.autoLockSeconds() }.catch { emit(DEFAULT_AUTO_LOCK_SECONDS) }

    suspend fun setAutoLockSeconds(value: Int) {
        context.dataStore.edit {
            it[Keys.AUTO_LOCK_SECONDS] = value.coerceIn(MIN_AUTO_LOCK_SECONDS, MAX_AUTO_LOCK_SECONDS)
        }
    }

    val lockOnScreenOffFlow: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.LOCK_ON_SCREEN_OFF] ?: false }.catch { emit(false) }

    suspend fun setLockOnScreenOff(value: Boolean) {
        context.dataStore.edit { it[Keys.LOCK_ON_SCREEN_OFF] = value }
    }

    val screenshotBlockedFlow: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.SCREENSHOT_BLOCKED] ?: true }.catch { emit(true) }

    suspend fun setScreenshotBlocked(value: Boolean) {
        context.dataStore.edit { it[Keys.SCREENSHOT_BLOCKED] = value }
    }

    private fun sanitizeClipboardClearSeconds(value: Int): Int =
        if (value < MIN_CLIPBOARD_CLEAR_SECONDS) DEFAULT_CLIPBOARD_CLEAR_SECONDS
        else value.coerceAtMost(MAX_CLIPBOARD_CLEAR_SECONDS)

    private fun Preferences.clipboardClearSeconds(): Int =
        sanitizeClipboardClearSeconds(this[Keys.CLIPBOARD_CLEAR_SECONDS] ?: DEFAULT_CLIPBOARD_CLEAR_SECONDS)

    val clipboardClearSecondsFlow: Flow<Int> =
        context.dataStore.data.map { it.clipboardClearSeconds() }.catch { emit(DEFAULT_CLIPBOARD_CLEAR_SECONDS) }

    suspend fun setClipboardClearSeconds(value: Int) {
        context.dataStore.edit {
            it[Keys.CLIPBOARD_CLEAR_SECONDS] = sanitizeClipboardClearSeconds(value)
        }
    }

    /** Whether the user permanently dismissed the home-screen autofill enablement banner. */
    val autofillBannerDismissedFlow: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.AUTOFILL_BANNER_DISMISSED] ?: false }.catch { emit(false) }

    suspend fun setAutofillBannerDismissed(value: Boolean) {
        context.dataStore.edit { it[Keys.AUTOFILL_BANNER_DISMISSED] = value }
    }

    /** Whether the password health-check feature is shown. Default on; users can hide it. */
    val healthCheckEnabledFlow: Flow<Boolean> =
        context.dataStore.data.map { it[Keys.HEALTH_CHECK_ENABLED] ?: true }.catch { emit(true) }

    suspend fun setHealthCheckEnabled(value: Boolean) {
        context.dataStore.edit { it[Keys.HEALTH_CHECK_ENABLED] = value }
    }

    // ---- Failed unlock tracking (brute force delay) ------------------------

    suspend fun failedAttempts(): Int = context.dataStore.data.first()[Keys.FAILED_ATTEMPTS] ?: 0
    suspend fun lastFailedAt(): Long = context.dataStore.data.first()[Keys.LAST_FAILED_AT] ?: 0L

    suspend fun recordFailure() {
        context.dataStore.edit {
            // Cap the persisted counter so repeated failures can never wrap Int back to a value
            // below the throttling threshold.
            it[Keys.FAILED_ATTEMPTS] = (it[Keys.FAILED_ATTEMPTS] ?: 0)
                .coerceAtLeast(0)
                .coerceAtMost(999) + 1
            it[Keys.LAST_FAILED_AT] = System.currentTimeMillis()
        }
    }

    suspend fun resetFailures() {
        context.dataStore.edit {
            it[Keys.FAILED_ATTEMPTS] = 0
            it[Keys.LAST_FAILED_AT] = 0L
        }
    }

    data class RiskSignals(
        val deviceTrusted: Boolean,
        val failedAttempts: Int,
        val successfulUnlocksInWindow: Int,
        val unlockWindowStartedAt: Long
    )

    /** Reads all risk inputs from one DataStore snapshot so policy decisions are consistent. */
    suspend fun riskSignals(): RiskSignals {
        val values = context.dataStore.data.first()
        return RiskSignals(
            deviceTrusted = values[Keys.DEVICE_TRUSTED] ?: false,
            failedAttempts = (values[Keys.FAILED_ATTEMPTS] ?: 0).coerceAtLeast(0),
            successfulUnlocksInWindow = (values[Keys.SUCCESSFUL_UNLOCKS_IN_WINDOW] ?: 0).coerceAtLeast(0),
            unlockWindowStartedAt = values[Keys.UNLOCK_WINDOW_STARTED_AT] ?: 0L
        )
    }

    /** Marks a device trusted only after a successful master credential authentication. */
    suspend fun recordSuccessfulCredentialAuthentication(nowMillis: Long, windowMillis: Long) {
        require(windowMillis > 0L) { "windowMillis must be positive" }
        context.dataStore.edit {
            val windowStart = it[Keys.UNLOCK_WINDOW_STARTED_AT] ?: 0L
            val withinWindow = windowStart > 0L && nowMillis >= windowStart && nowMillis - windowStart <= windowMillis
            it[Keys.UNLOCK_WINDOW_STARTED_AT] = if (withinWindow) windowStart else nowMillis
            it[Keys.SUCCESSFUL_UNLOCKS_IN_WINDOW] = if (withinWindow) {
                ((it[Keys.SUCCESSFUL_UNLOCKS_IN_WINDOW] ?: 0).coerceAtLeast(0) + 1).coerceAtMost(100)
            } else {
                1
            }
            it[Keys.DEVICE_TRUSTED] = true
        }
    }
}
