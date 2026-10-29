package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.DatabaseWriteOutcomeException
import java.util.concurrent.atomic.AtomicBoolean
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.data.model.TagCodec
import com.offlinevault.data.model.CustomField
import com.offlinevault.data.model.CustomFieldCodec
import com.offlinevault.security.SessionManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class EditFormState(
    val id: String? = null,
    val vaultId: String = "",
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val tags: String = "",
    val note: String = "",
    val isEditing: Boolean = false,
    val customFields: List<CustomField> = emptyList()
)

class PasswordEditViewModel(
    private val passwordRepository: PasswordRepository,
    private val vaultRepository: VaultRepository
) : ViewModel() {

    private val _form = MutableStateFlow(EditFormState())
    val form: StateFlow<EditFormState> = _form.asStateFlow()
    private val initialForm = MutableStateFlow(EditFormState())
    val hasUnsavedChanges: StateFlow<Boolean> =
        combine(_form, initialForm) { current, initial -> current != initial }
            .stateIn(viewModelScope, SharingStarted.Eagerly, false)

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private val _isSaving = MutableStateFlow(false)
    val isSaving: StateFlow<Boolean> = _isSaving.asStateFlow()

    private val _isReady = MutableStateFlow(false)
    val isReady: StateFlow<Boolean> = _isReady.asStateFlow()

    private var loadedKey: String? = null
    private var loadJob: Job? = null
    private var saveJob: Job? = null

    init {
        viewModelScope.launch {
            SessionManager.unlocked.collect { unlocked ->
                if (!unlocked) {
                    loadJob?.cancel()
                    saveJob?.cancel()
                    loadedKey = null
                    _isReady.value = false
                    setInitialForm(EditFormState())
                    _errorMessage.value = null
                    _isSaving.value = false
                }
            }
        }
    }

    /** Loads either a new (vaultId set) or existing (passwordId set) form exactly once per target. */
    fun initialize(vaultId: String, passwordId: String?) {
        val key = "$vaultId|$passwordId"
        if (loadedKey == key) return
        loadedKey = key
        loadJob?.cancel()
        _isReady.value = false
        setInitialForm(EditFormState(vaultId = vaultId, id = passwordId, isEditing = passwordId != null))
        _errorMessage.value = null

        if (passwordId == null) {
            _isReady.value = SessionManager.isUnlocked
        } else {
            loadJob = viewModelScope.launch {
                try {
                    val generation = SessionManager.requireActiveSession()
                    val item = withContext(Dispatchers.Default) { passwordRepository.getDecrypted(passwordId) }
                    if (loadedKey != key) return@launch
                    if (item != null) {
                        SessionManager.withActiveSessionNow(generation) {
                            setInitialForm(EditFormState(
                                id = item.id,
                                vaultId = item.vaultId,
                                title = item.title,
                                username = item.username,
                                password = item.password,
                                url = item.url,
                                tags = item.tags.joinToString("\n"),
                                note = item.note,
                                isEditing = true,
                                customFields = item.customFields
                            ))
                            _isReady.value = true
                        }
                    } else {
                        _errorMessage.value = "未找到这条密码"
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    _errorMessage.value = "无法读取这条密码"
                }
            }
        }
    }

    fun update(transform: (EditFormState) -> EditFormState) {
        if (!_isReady.value || _isSaving.value || !SessionManager.isUnlocked) return
        _form.value = transform(_form.value)
    }

    fun setPassword(value: String) = update { it.copy(password = value) }

    fun save(onResult: (Boolean, String?) -> Unit) {
        if (saveJob?.isActive == true) return
        if (!_isReady.value) {
            onResult(false, "密码尚未加载，请返回后重试")
            return
        }
        val f = _form.value
        try { CustomFieldCodec.validate(f.customFields) } catch (_: Exception) {
            onResult(false, "请检查安全字段名称、长度和 TOTP 配置")
            return
        }
        if (listOf(f.title, f.username, f.password, f.url, f.tags, f.note).all(String::isBlank) && f.customFields.isEmpty()) {
            onResult(false, "请至少填写标题、用户名、密码、网址、标签或备注中的一项")
            return
        }
        saveJob = viewModelScope.launch {
            _isSaving.value = true
            val generation = SessionManager.sessionGeneration
            val committed = AtomicBoolean(false)
            try {
                SessionManager.requireActiveSession(generation)
                val tags = TagCodec.normalize(f.tags.lines())
                withContext(Dispatchers.Default) {
                    SessionManager.requireActiveSession(generation)
                    passwordRepository.save(
                        id = f.id,
                        vaultId = f.vaultId,
                        title = f.title.ifBlank { f.username.ifBlank { "无标题" } },
                        username = f.username,
                        password = f.password,
                        url = f.url,
                        tags = tags,
                        note = f.note,
                        customFields = f.customFields
                    )
                    // Survives prompt cancellation while dispatching the result back to Main.
                    committed.set(true)
                }
                SessionManager.withActiveSessionNow(generation) {
                    initialForm.value = f
                    onResult(true, null)
                }
            } catch (e: CancellationException) {
                if (committed.get()) {
                    try {
                        SessionManager.withActiveSessionNow(generation) {
                            _isReady.value = false
                            _errorMessage.value = "操作已保存，请返回列表核对，不要重复保存"
                        }
                    } catch (_: com.offlinevault.security.VaultLockedException) {
                        // The old form has already been cleared on lock.
                    }
                }
                throw e
            } catch (e: DatabaseWriteOutcomeException) {
                // An uncertain insert must be reconciled from the list, not retried with a new ID.
                try {
                    SessionManager.withActiveSessionNow(generation) {
                        _isReady.value = false
                        onResult(false, e.message)
                    }
                } catch (_: com.offlinevault.security.VaultLockedException) {
                }
            } catch (_: com.offlinevault.security.VaultLockedException) {
                // Never deliver a late result into a subsequent authentication session.
            } catch (_: Exception) {
                onResult(false, "保存失败，请重新解锁后重试")
            } finally {
                _isSaving.value = false
            }
        }
    }

    fun clearError() {
        _errorMessage.value = null
    }

    private fun setInitialForm(value: EditFormState) {
        initialForm.value = value
        _form.value = value
    }
}
