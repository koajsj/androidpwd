package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.backup.BackupManager
import com.offlinevault.data.backup.ImportConflictStrategy
import com.offlinevault.data.backup.ImportPreview
import com.offlinevault.data.backup.ImportResult
import com.offlinevault.data.model.VaultEntity
import com.offlinevault.data.preferences.SecurityPreferences
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.security.KeyManager
import com.offlinevault.security.KeystoreManager
import com.offlinevault.security.UnlockResult
import com.offlinevault.security.SessionManager
import com.offlinevault.security.VaultLockedException
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job
import javax.crypto.Cipher
import java.security.InvalidKeyException
import android.security.keystore.KeyPermanentlyInvalidatedException

class SettingsViewModel(
    private val keyManager: KeyManager,
    private val prefs: SecurityPreferences,
    private val backupManager: BackupManager,
    private val vaultRepository: VaultRepository
) : ViewModel() {

    private var changeMasterJob: Job? = null
    private var changeRecoveryJob: Job? = null
    private var verifyMasterJob: Job? = null
    private var changeMnemonicJob: Job? = null
    private var disableMnemonicJob: Job? = null

    data class ExportPayload(
        val content: String? = null,
        val errorMessage: String? = null,
        val validated: Boolean = false
    )

    data class ImportPreviewPayload(
        val preview: ImportPreview? = null,
        val errorMessage: String? = null
    )

    val biometricEnabled: StateFlow<Boolean> =
        prefs.biometricEnabledFlow.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    val autoLockSeconds: StateFlow<Int> =
        prefs.autoLockSecondsFlow.stateIn(viewModelScope, SharingStarted.Eagerly, 60)

    val screenshotBlocked: StateFlow<Boolean> =
        prefs.screenshotBlockedFlow.stateIn(viewModelScope, SharingStarted.Eagerly, true)

    val lockOnScreenOff: StateFlow<Boolean> =
        prefs.lockOnScreenOffFlow.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    val healthCheckEnabled: StateFlow<Boolean> =
        prefs.healthCheckEnabledFlow.stateIn(viewModelScope, SharingStarted.Eagerly, true)

    val clipboardClearSeconds: StateFlow<Int> =
        prefs.clipboardClearSecondsFlow.stateIn(viewModelScope, SharingStarted.Eagerly, 10)

    val recoveryQuestion: StateFlow<String> =
        prefs.recoveryQuestionFlow.stateIn(viewModelScope, SharingStarted.Eagerly, "")

    val mnemonicEnabled: StateFlow<Boolean> =
        prefs.mnemonicEnabledFlow.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    val credentialType: StateFlow<com.offlinevault.security.CredentialType> =
        prefs.credentialTypeFlow
            .map { com.offlinevault.security.CredentialType.fromKey(it) }
            .stateIn(viewModelScope, SharingStarted.Eagerly, com.offlinevault.security.CredentialType.PIN6)

    val vaults: StateFlow<List<VaultEntity>> =
        vaultRepository.allVaults()
            .catch { error ->
                if (error is CancellationException) throw error
                emit(emptyList())
            }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    // ---- Settings toggles --------------------------------------------------

    fun setAutoLockSeconds(value: Int, onResult: (Boolean) -> Unit = {}) = viewModelScope.launch {
        onResult(runAction { prefs.setAutoLockSeconds(value) })
    }

    fun setScreenshotBlocked(value: Boolean, onResult: (Boolean) -> Unit = {}) = viewModelScope.launch {
        onResult(runAction { prefs.setScreenshotBlocked(value) })
    }

    fun setLockOnScreenOff(value: Boolean, onResult: (Boolean) -> Unit = {}) = viewModelScope.launch {
        onResult(runAction { prefs.setLockOnScreenOff(value) })
    }

    fun setHealthCheckEnabled(value: Boolean, onResult: (Boolean) -> Unit = {}) = viewModelScope.launch {
        onResult(runAction { prefs.setHealthCheckEnabled(value) })
    }

    fun setClipboardSeconds(value: Int, onResult: (Boolean) -> Unit = {}) = viewModelScope.launch {
        onResult(runAction { prefs.setClipboardClearSeconds(value) })
    }

    // ---- Master password / recovery ---------------------------------------

    fun changeMasterPassword(old: String, new: String, onResult: (Boolean, String?) -> Unit) {
        if (changeMasterJob?.isActive == true) return
        changeMasterJob = viewModelScope.launch {
            try {
                when (val result = withContext(Dispatchers.Default) { keyManager.changeMasterPassword(old, new) }) {
                    is UnlockResult.Success -> onResult(true, null)
                    is UnlockResult.WrongCredential -> onResult(false, "当前密码不正确")
                    is UnlockResult.Delayed -> onResult(
                        false,
                        "失败次数过多，请在 ${result.secondsRemaining} 秒后重试"
                    )
                    is UnlockResult.Error -> onResult(false, result.message)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "无法修改密码")
            }
        }
    }

    fun changeRecovery(question: String, answer: String, onResult: (Boolean, String?) -> Unit) {
        if (answer.trim().length < KeyManager.MIN_NEW_RECOVERY_ANSWER_LENGTH) {
            onResult(false, "安全问题答案至少需要 ${KeyManager.MIN_NEW_RECOVERY_ANSWER_LENGTH} 个字符")
            return
        }
        if (changeRecoveryJob?.isActive == true) return
        changeRecoveryJob = viewModelScope.launch {
            try {
                withContext(Dispatchers.Default) { keyManager.changeRecovery(question.trim(), answer) }
                onResult(true, null)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "无法更新安全问题")
            }
        }
    }

    fun authorizeMnemonicRecoveryUpdate(masterPassword: String, onResult: (Boolean, String?) -> Unit) {
        if (verifyMasterJob?.isActive == true) return
        verifyMasterJob = viewModelScope.launch {
            try {
                when (val result = withContext(Dispatchers.Default) {
                    keyManager.authorizeMnemonicRecoveryUpdate(masterPassword)
                }) {
                    is UnlockResult.Success -> onResult(true, null)
                    is UnlockResult.WrongCredential -> onResult(false, "当前密码不正确")
                    is UnlockResult.Delayed -> onResult(false, "失败次数过多，请在 ${result.secondsRemaining} 秒后重试")
                    is UnlockResult.Error -> onResult(false, result.message)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "无法验证当前密码")
            }
        }
    }

    /** The UI verifies the current master password immediately before calling this method. */
    fun updateMnemonicRecoveryForUnlockedSession(mnemonicPhrase: String, onResult: (Boolean, String?) -> Unit) {
        if (changeMnemonicJob?.isActive == true) return
        changeMnemonicJob = viewModelScope.launch {
            try {
                when (val result = withContext(Dispatchers.Default) {
                    keyManager.updateMnemonicRecoveryForUnlockedSession(mnemonicPhrase)
                }) {
                    is UnlockResult.Success -> onResult(true, null)
                    is UnlockResult.WrongCredential -> onResult(false, "当前密码不正确")
                    is UnlockResult.Delayed -> onResult(false, "失败次数过多，请在 ${result.secondsRemaining} 秒后重试")
                    is UnlockResult.Error -> onResult(false, result.message)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "无法更新助记词")
            }
        }
    }

    fun disableMnemonicRecovery(masterPassword: String, onResult: (Boolean, String?) -> Unit) {
        if (disableMnemonicJob?.isActive == true) return
        disableMnemonicJob = viewModelScope.launch {
            try {
                when (val result = withContext(Dispatchers.Default) {
                    keyManager.disableMnemonicRecovery(masterPassword)
                }) {
                    is UnlockResult.Success -> onResult(true, null)
                    is UnlockResult.WrongCredential -> onResult(false, "当前密码不正确")
                    is UnlockResult.Delayed -> onResult(false, "失败次数过多，请在 ${result.secondsRemaining} 秒后重试")
                    is UnlockResult.Error -> onResult(false, result.message)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "无法关闭助记词恢复")
            }
        }
    }

    // ---- Biometric ---------------------------------------------------------

    /** Builds an ENCRYPT cipher to enable biometric unlock. Null if Keystore key creation failed. */
    fun prepareEnableBiometricCipher(onReady: (Cipher?) -> Unit) {
        viewModelScope.launch {
            // Do not delete a working key before the user actually completes the system prompt.
            // Otherwise cancelling a re-enable attempt would silently break an already usable
            // biometric unlock. Enrollment changes already invalidate the key at the Keystore
            // level; only rebuild when the existing material can no longer initialise a Cipher.
            val cipher = withContext(Dispatchers.Default) {
                try {
                    KeystoreManager.encryptCipher()
                } catch (_: KeyPermanentlyInvalidatedException) {
                    runCatching { KeystoreManager.recreateBiometricEncryptCipher() }.getOrNull()
                } catch (_: InvalidKeyException) {
                    runCatching { KeystoreManager.recreateBiometricEncryptCipher() }.getOrNull()
                } catch (_: Exception) {
                    null
                }
            }
            onReady(cipher)
        }
    }

    fun finishEnableBiometric(cipher: Cipher, onDone: (Boolean) -> Unit) {
        viewModelScope.launch {
            val success = try {
                withContext(Dispatchers.Default) { keyManager.storeBiometricWrappedDek(cipher) }
                true
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                false
            }
            onDone(success)
        }
    }

    fun disableBiometric(onResult: (Boolean) -> Unit = {}) {
        viewModelScope.launch {
            onResult(withContext(Dispatchers.Default) { runAction { keyManager.disableBiometric() } })
        }
    }

    // ---- Import / export ---------------------------------------------------

    fun buildEncryptedJsonBackup(password: String, onResult: (ExportPayload) -> Unit) {
        val generation = SessionManager.sessionGeneration
        viewModelScope.launch {
            val result = try {
                ExportPayload(
                    content = withContext(Dispatchers.Default) {
                        backupManager.buildEncryptedJsonBackup(password)
                    },
                    validated = true
                )
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                ExportPayload(errorMessage = "无法创建加密备份")
            }
            publishForSession(generation, { onResult(result) }) {
                onResult(ExportPayload(errorMessage = "密码库已锁定，请重新解锁后导出"))
            }
        }
    }

    fun previewJsonImport(content: String, password: String, onResult: (ImportPreviewPayload) -> Unit) {
        val generation = SessionManager.sessionGeneration
        viewModelScope.launch {
            val result = try {
                ImportPreviewPayload(
                    preview = withContext(Dispatchers.Default) {
                        backupManager.previewJsonBackup(content, password)
                    }
                )
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                ImportPreviewPayload(errorMessage = "无法预览备份：密码错误、格式无效或文件已损坏")
            }
            publishForSession(generation, { onResult(result) }) {
                onResult(ImportPreviewPayload(errorMessage = "密码库已锁定，请重新解锁后导入"))
            }
        }
    }

    fun previewCsvImport(content: String, vaultId: String, onResult: (ImportPreviewPayload) -> Unit) {
        val generation = SessionManager.sessionGeneration
        viewModelScope.launch {
            val result = try {
                ImportPreviewPayload(
                    preview = withContext(Dispatchers.Default) {
                        backupManager.previewChromeCsv(content, vaultId)
                    }
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: IllegalArgumentException) {
                ImportPreviewPayload(errorMessage = e.message ?: "无法预览 CSV")
            } catch (_: Exception) {
                ImportPreviewPayload(errorMessage = "无法预览 CSV")
            }
            publishForSession(generation, { onResult(result) }) {
                onResult(ImportPreviewPayload(errorMessage = "密码库已锁定，请重新解锁后导入"))
            }
        }
    }

    fun buildCsv(vaultId: String, slim: Boolean, onResult: (ExportPayload) -> Unit) {
        val generation = SessionManager.sessionGeneration
        viewModelScope.launch {
            val result = try {
                ExportPayload(
                    content = withContext(Dispatchers.Default) { backupManager.buildCsvForVault(vaultId, slim) }
                )
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                ExportPayload(errorMessage = "无法导出 CSV")
            }
            publishForSession(generation, { onResult(result) }) {
                onResult(ExportPayload(errorMessage = "密码库已锁定，请重新解锁后导出"))
            }
        }
    }

    fun importJson(
        content: String,
        password: String,
        strategy: ImportConflictStrategy = ImportConflictStrategy.SKIP,
        onResult: (ImportResult) -> Unit
    ) {
        viewModelScope.launch {
            val result = try {
                withContext(Dispatchers.Default) { backupManager.importJsonBackup(content, password, strategy) }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                ImportResult(0, 0, 0, listOf("导入失败，请检查文件后重试"))
            }
            onResult(result)
        }
    }

    fun importCsv(
        content: String,
        vaultId: String,
        strategy: ImportConflictStrategy = ImportConflictStrategy.SKIP,
        onResult: (ImportResult) -> Unit
    ) {
        viewModelScope.launch {
            val result = try {
                withContext(Dispatchers.Default) { backupManager.importChromeCsv(content, vaultId, strategy) }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                ImportResult(0, 0, 0, listOf("导入失败，请检查文件后重试"))
            }
            onResult(result)
        }
    }

    private fun publishForSession(generation: Long, publish: () -> Unit, onLocked: () -> Unit) {
        try {
            SessionManager.withActiveSessionNow(generation, publish)
        } catch (_: VaultLockedException) {
            onLocked()
        }
    }

    private suspend fun runAction(block: suspend () -> Unit): Boolean = try {
        block()
        true
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        false
    }
}
