package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.repository.DecryptedPassword
import com.offlinevault.data.repository.PasswordHistoryItem
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.DatabaseWriteOutcomeException
import com.offlinevault.security.SessionManager
import com.offlinevault.security.VaultLockedException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

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
    private val _item = MutableStateFlow<DecryptedPassword?>(null)
    val item: StateFlow<DecryptedPassword?> = _item.asStateFlow()

    init {
        viewModelScope.launch {
            // Observe only while the detail UI is collecting; do not decrypt off-screen updates.
            combine(id, _item.subscriptionCount) { pid, subscribers ->
                pid.takeIf { subscribers > 0 }
            }.distinctUntilChanged().flatMapLatest { pid ->
                if (pid == null) flowOf(null)
                else passwordRepository.observe(pid).catch { error ->
                    if (error is CancellationException) throw error
                    if (error !is VaultLockedException) {
                        _error.value = "无法读取这条凭据。"
                    }
                    emit(null)
                }
            }.collectLatest { entity ->
                if (entity == null) {
                    _item.value = null
                } else {
                    try {
                        val generation = SessionManager.requireActiveSession()
                        val decrypted = withContext(Dispatchers.Default) {
                            SessionManager.withActiveSession {
                                SessionManager.requireActiveSession(generation)
                                passwordRepository.decryptForActiveSession(entity)
                            }
                        }
                        SessionManager.withActiveSessionNow(generation) {
                            if (id.value == entity.id && _item.subscriptionCount.value > 0) {
                                _item.value = decrypted
                            }
                        }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: VaultLockedException) {
                        _item.value = null
                    } catch (e: Exception) {
                        _error.value = "这条凭据已损坏，无法解密。"
                        _item.value = null
                    }
                }
            }
        }
    }

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

    init {
        viewModelScope.launch {
            SessionManager.unlocked.collect { unlocked ->
                if (!unlocked) {
                    historyJob?.cancel()
                    _history.value = emptyList()
                    _item.value = null
                    id.value = null
                    _error.value = null
                }
            }
        }
    }

    fun load(passwordId: String) {
        if (id.value != passwordId) {
            historyJob?.cancel()
            _history.value = emptyList()
            _item.value = null
        }
        _error.value = null
        id.value = passwordId
    }

    fun loadHistory() {
        val pid = id.value ?: return
        if (historyJob?.isActive == true) return
        historyJob = viewModelScope.launch {
            try {
                val generation = SessionManager.requireActiveSession()
                val result = withContext(Dispatchers.Default) {
                    SessionManager.withActiveSession {
                        SessionManager.requireActiveSession(generation)
                        passwordRepository.history(pid)
                    }
                }
                SessionManager.withActiveSessionNow(generation) {
                    if (id.value == pid) _history.value = result
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                _history.value = emptyList()
            }
        }
    }

    /** Drops decrypted history from memory when the history view closes. */
    fun clearHistory() {
        historyJob?.cancel()
        historyJob = null
        _history.value = emptyList()
    }

    fun delete(onResult: (Boolean, String?) -> Unit) {
        if (deleteJob?.isActive == true) return
        val pid = id.value ?: return onResult(true, null)
        deleteJob = viewModelScope.launch {
            val generation = SessionManager.sessionGeneration
            try {
                passwordRepository.deleteById(pid)
                SessionManager.withActiveSessionNow(generation) { onResult(true, null) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: DatabaseWriteOutcomeException) {
                if (SessionManager.isUnlocked && SessionManager.sessionGeneration == generation) onResult(false, e.message)
            } catch (_: com.offlinevault.security.VaultLockedException) {
            } catch (_: Exception) {
                onResult(false, "删除失败，请重新解锁后重试")
            }
        }
    }
}
