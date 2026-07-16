package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.preferences.SecurityPreferences
import com.offlinevault.security.CredentialType
import com.offlinevault.security.KeyManager
import com.offlinevault.security.SessionManager
import com.offlinevault.security.UnlockResult
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job
import javax.crypto.Cipher

enum class AppLockState { LOADING, SETUP, LOCKED, UNLOCKED }

data class UnlockUiState(
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val delaySeconds: Int = 0,
    val shakeTrigger: Int = 0
)

class AuthViewModel(
    private val keyManager: KeyManager,
    private val prefs: SecurityPreferences
) : ViewModel() {

    /** Top-level lock state driving navigation between setup / unlock / main. */
    val lockState: StateFlow<AppLockState> =
        combine(prefs.initializedFlow, SessionManager.unlocked) { initialized, unlocked ->
            when {
                !initialized -> AppLockState.SETUP
                unlocked -> AppLockState.UNLOCKED
                else -> AppLockState.LOCKED
            }
        }.stateIn(viewModelScope, SharingStarted.Eagerly, AppLockState.LOADING)

    val biometricEnabled: StateFlow<Boolean> =
        prefs.biometricEnabledFlow.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    val recoveryQuestion: StateFlow<String> =
        prefs.recoveryQuestionFlow.stateIn(viewModelScope, SharingStarted.Eagerly, "")

    val mnemonicEnabled: StateFlow<Boolean> =
        prefs.mnemonicEnabledFlow.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    val credentialType: StateFlow<CredentialType> =
        prefs.credentialTypeFlow
            .map { CredentialType.fromKey(it) }
            .stateIn(viewModelScope, SharingStarted.Eagerly, CredentialType.PIN6)

    private val _unlockState = MutableStateFlow(UnlockUiState())
    val unlockState: StateFlow<UnlockUiState> = _unlockState.asStateFlow()

    private val _setupError = MutableStateFlow<String?>(null)
    val setupError: StateFlow<String?> = _setupError.asStateFlow()
    private val _setupInProgress = MutableStateFlow(false)
    val setupInProgress: StateFlow<Boolean> = _setupInProgress.asStateFlow()
    private var setupJob: Job? = null
    private var unlockJob: Job? = null

    fun setup(
        masterPassword: String,
        recoveryQuestion: String,
        recoveryAnswer: String,
        credentialType: CredentialType,
        mnemonicPhrase: String
    ) {
        if (setupJob?.isActive == true) return
        setupJob = viewModelScope.launch {
            _setupError.value = null
            _setupInProgress.value = true
            try {
                prefs.setCredentialType(credentialType.key)
                withContext(Dispatchers.Default) {
                    keyManager.setup(masterPassword, recoveryQuestion.trim(), recoveryAnswer, mnemonicPhrase)
                }
                _setupError.value = null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Do not expose internal storage / crypto exception details on a sensitive screen.
                _setupError.value = "创建密码库失败，请检查输入后重试"
            } finally {
                _setupInProgress.value = false
            }
        }
    }

    fun unlockWithPassword(password: String) {
        if (unlockJob?.isActive == true) return
        unlockJob = viewModelScope.launch {
            _unlockState.value = _unlockState.value.copy(isLoading = true, errorMessage = null)
            val result = try {
                withContext(Dispatchers.Default) { keyManager.unlockWithPassword(password) }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                _unlockState.value = _unlockState.value.copy(
                    isLoading = false,
                    errorMessage = "解锁失败，请重试"
                )
                return@launch
            }
            when (result) {
                is UnlockResult.Success ->
                    _unlockState.value = UnlockUiState()
                is UnlockResult.WrongCredential ->
                    _unlockState.value = _unlockState.value.copy(
                        isLoading = false,
                        errorMessage = "主密码错误",
                        shakeTrigger = _unlockState.value.shakeTrigger + 1
                    )
                is UnlockResult.Delayed ->
                    _unlockState.value = _unlockState.value.copy(
                        isLoading = false,
                        errorMessage = "尝试次数过多，请在 ${result.secondsRemaining} 秒后重试",
                        delaySeconds = result.secondsRemaining,
                        shakeTrigger = _unlockState.value.shakeTrigger + 1
                    )
                is UnlockResult.Error ->
                    _unlockState.value = _unlockState.value.copy(
                        isLoading = false,
                        errorMessage = result.message
                    )
            }
        }
    }

    /** Returns a biometric-bound decrypt cipher (or null if biometric isn't usable). */
    fun prepareBiometricCipher(onReady: (Cipher?) -> Unit) {
        viewModelScope.launch {
            val cipher = try {
                withContext(Dispatchers.Default) { keyManager.biometricDecryptCipher() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                null
            }
            if (cipher == null && biometricEnabled.value) {
                try {
                    withContext(Dispatchers.Default) { keyManager.disableBiometric() }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    // The password path remains available even if stale biometric state persists.
                }
                _unlockState.value = _unlockState.value.copy(
                    errorMessage = "指纹解锁已失效，请使用主密码并在设置中重新启用"
                )
            }
            onReady(cipher)
        }
    }

    fun finishBiometricUnlock(cipher: Cipher) {
        viewModelScope.launch {
            try {
                when (val result = withContext(Dispatchers.Default) {
                    keyManager.unlockWithBiometricCipher(cipher)
                }) {
                    is UnlockResult.Success -> _unlockState.value = UnlockUiState()
                    is UnlockResult.Error ->
                        _unlockState.value = _unlockState.value.copy(errorMessage = result.message)
                    else -> _unlockState.value = _unlockState.value.copy(errorMessage = "指纹解锁失败")
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                _unlockState.value = _unlockState.value.copy(errorMessage = "指纹解锁失败")
            }
        }
    }

    fun recover(answer: String, newMasterPassword: String, onResult: (Boolean, String?) -> Unit) {
        viewModelScope.launch {
            try {
                when (val result = withContext(Dispatchers.Default) { keyManager.recoverWithAnswer(answer, newMasterPassword) }) {
                    is UnlockResult.Success -> onResult(true, "主密码已重置，请使用新主密码重新解锁")
                    is UnlockResult.WrongCredential -> onResult(false, "安全问题答案错误")
                    is UnlockResult.Delayed -> onResult(false, "尝试次数过多，请在 ${result.secondsRemaining} 秒后重试")
                    is UnlockResult.Error -> onResult(false, result.message)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "恢复失败")
            }
        }
    }

    fun recoverWithMnemonic(mnemonic: String, newMasterPassword: String, onResult: (Boolean, String?) -> Unit) {
        viewModelScope.launch {
            try {
                when (val result = withContext(Dispatchers.Default) {
                    keyManager.recoverWithMnemonic(mnemonic, newMasterPassword)
                }) {
                    is UnlockResult.Success -> onResult(true, "主密码已重置，请使用新主密码重新解锁")
                    is UnlockResult.WrongCredential -> onResult(false, "助记词错误")
                    is UnlockResult.Delayed -> onResult(false, "尝试次数过多，请在 ${result.secondsRemaining} 秒后重试")
                    is UnlockResult.Error -> onResult(false, result.message)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "恢复失败")
            }
        }
    }

    fun lock() = keyManager.lock()
}
