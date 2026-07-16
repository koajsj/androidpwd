package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.repository.DecryptedPassword
import com.offlinevault.data.repository.PasswordHistoryItem
import com.offlinevault.data.repository.PasswordRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job

@OptIn(ExperimentalCoroutinesApi::class)
class PasswordDetailViewModel(
    private val passwordRepository: PasswordRepository
) : ViewModel() {

    private val id = MutableStateFlow<String?>(null)
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()
    private var deleteJob: Job? = null

    /**
     * Observes the underlying row so the screen always reflects the latest edit, and collapses to
     * null if the item is deleted. Decryption happens on each emission using the active session key.
     */
    val item: StateFlow<DecryptedPassword?> =
        id.flatMapLatest { pid ->
            if (pid == null) flowOf(null)
            else passwordRepository.observe(pid).map { entity ->
                entity?.let {
                    try {
                        passwordRepository.decrypt(it)
                    } catch (e: Exception) {
                        _error.value = "这条凭据已损坏，无法解密。"
                        null
                    }
                }
            }.catch { error ->
                if (error is CancellationException) throw error
                _error.value = "这条凭据已损坏，无法解密。"
                emit(null)
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    /** Live count of previous passwords, for the "历史密码 (N)" entry. */
    val historyCount: StateFlow<Int> =
        id.flatMapLatest { pid ->
            if (pid == null) flowOf(0) else passwordRepository.historyCount(pid)
        }.catch { error ->
            if (error is CancellationException) throw error
            emit(0)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    // Decrypted history is loaded only on demand so old plaintext passwords aren't held in memory
    // unless the user explicitly opens the history view.
    private val _history = MutableStateFlow<List<PasswordHistoryItem>>(emptyList())
    val history: StateFlow<List<PasswordHistoryItem>> = _history.asStateFlow()
    private var historyJob: Job? = null

    fun load(passwordId: String) {
        if (id.value != passwordId) {
            historyJob?.cancel()
            _history.value = emptyList()
        }
        _error.value = null
        id.value = passwordId
    }

    fun loadHistory() {
        val pid = id.value ?: return
        if (historyJob?.isActive == true) return
        historyJob = viewModelScope.launch {
            _history.value = try {
                passwordRepository.history(pid)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                emptyList()
            }
        }
    }

    /** Drops decrypted history from memory when the history view closes. */
    fun clearHistory() {
        _history.value = emptyList()
    }

    fun delete(onResult: (Boolean, String?) -> Unit) {
        if (deleteJob?.isActive == true) return
        val pid = id.value ?: return onResult(true, null)
        deleteJob = viewModelScope.launch {
            try {
                passwordRepository.deleteById(pid)
                onResult(true, null)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "删除失败，请重新解锁后重试")
            }
        }
    }
}
