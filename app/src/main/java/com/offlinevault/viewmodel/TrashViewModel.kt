package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.DatabaseWriteOutcomeException
import com.offlinevault.security.SessionManager
import com.offlinevault.security.VaultLockedException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** Drives the recycle-bin screen: lists trashed credentials and restores / erases them. */
class TrashViewModel(
    private val passwordRepository: PasswordRepository
) : ViewModel() {

    val items: StateFlow<List<PasswordEntity>> =
        passwordRepository.trashed()
            .flowOn(Dispatchers.Default)
            .catch { error ->
                if (error is CancellationException) throw error
                emit(emptyList())
            }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    fun restore(id: String, onResult: (Boolean, String?) -> Unit = { _, _ -> }) {
        runAction(onResult) { passwordRepository.restore(id) }
    }

    fun deleteForever(id: String, onResult: (Boolean, String?) -> Unit = { _, _ -> }) {
        runAction(onResult) { passwordRepository.permanentlyDelete(id) }
    }

    fun emptyTrash(onResult: (Boolean, String?) -> Unit = { _, _ -> }) {
        runAction(onResult) { passwordRepository.emptyTrash() }
    }

    private fun runAction(onResult: (Boolean, String?) -> Unit, block: suspend () -> Unit) {
        viewModelScope.launch {
            val generation = SessionManager.sessionGeneration
            val result = try {
                block()
                true to null
            } catch (e: CancellationException) {
                throw e
            } catch (e: DatabaseWriteOutcomeException) {
                false to e.message
            } catch (_: VaultLockedException) {
                return@launch
            } catch (_: Exception) {
                false to "操作失败"
            }
            try {
                SessionManager.withActiveSessionNow(generation) { onResult(result.first, result.second) }
            } catch (_: VaultLockedException) {
                // The old page is gone; do not deliver its callback into a new session.
            }
        }
    }
}
