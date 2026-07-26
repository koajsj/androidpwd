package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.security.SessionManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job

data class EditFormState(
    val id: String? = null,
    val vaultId: String = "",
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val tags: String = "",
    val note: String = "",
    val isEditing: Boolean = false
)

class PasswordEditViewModel(
    private val passwordRepository: PasswordRepository,
    private val vaultRepository: VaultRepository
) : ViewModel() {

    private val _form = MutableStateFlow(EditFormState())
    val form: StateFlow<EditFormState> = _form.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private val _isSaving = MutableStateFlow(false)
    val isSaving: StateFlow<Boolean> = _isSaving.asStateFlow()

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
                    _form.value = EditFormState()
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
        _errorMessage.value = null

        if (passwordId == null) {
            _form.value = EditFormState(vaultId = vaultId, isEditing = false)
        } else {
            loadJob = viewModelScope.launch {
                try {
                    val item = passwordRepository.getDecrypted(passwordId)
                    if (loadedKey != key) return@launch
                    if (item != null) {
                        _form.value = EditFormState(
                            id = item.id,
                            vaultId = item.vaultId,
                            title = item.title,
                            username = item.username,
                            password = item.password,
                            url = item.url,
                            tags = item.tags.joinToString(", "),
                            note = item.note,
                            isEditing = true
                        )
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
        _form.value = transform(_form.value)
    }

    fun setPassword(value: String) = update { it.copy(password = value) }

    fun save(onResult: (Boolean, String?) -> Unit) {
        if (saveJob?.isActive == true) return
        val f = _form.value
        if (listOf(f.title, f.username, f.password, f.url, f.tags, f.note).all(String::isBlank)) {
            onResult(false, "请至少填写标题、用户名、密码、网址、标签或备注中的一项")
            return
        }
        saveJob = viewModelScope.launch {
            _isSaving.value = true
            try {
                val tags = f.tags.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                passwordRepository.save(
                    id = f.id,
                    vaultId = f.vaultId,
                    title = f.title.ifBlank { f.username.ifBlank { "无标题" } },
                    username = f.username,
                    password = f.password,
                    url = f.url,
                    tags = tags,
                    note = f.note
                )
                vaultRepository.touch(f.vaultId)
                onResult(true, null)
            } catch (e: CancellationException) {
                throw e
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
}
