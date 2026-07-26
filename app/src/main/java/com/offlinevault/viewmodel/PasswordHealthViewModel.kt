package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.repository.PasswordHealthCandidate
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.security.SessionManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Computes an offline "password health" report: weak, reused and stale credentials. Results are
 * reduced to id/title/username only so plaintext passwords are NOT retained in UI state.
 */
class PasswordHealthViewModel(
    private val passwordRepository: PasswordRepository
) : ViewModel() {

    data class HealthEntry(val id: String, val title: String, val username: String)

    data class HealthReport(
        val total: Int = 0,
        val weak: List<HealthEntry> = emptyList(),
        val reused: List<HealthEntry> = emptyList(),
        val stale: List<HealthEntry> = emptyList()
    )

    data class UiState(
        val loading: Boolean = true,
        val error: String? = null,
        val report: HealthReport = HealthReport()
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()
    private var loadJob: Job? = null

    private companion object {
        const val WEAK_SCORE_BELOW = 40
        const val STALE_DAYS = 180
    }

    init {
        viewModelScope.launch {
            SessionManager.unlocked.collect { unlocked ->
                if (!unlocked) {
                    loadJob?.cancel()
                    _state.value = UiState(loading = false)
                }
            }
        }
    }

    fun load() {
        if (loadJob?.isActive == true) return
        _state.value = UiState(loading = true)
        loadJob = viewModelScope.launch {
            try {
                val report = withContext(Dispatchers.Default) { buildReport() }
                _state.value = UiState(loading = false, report = report)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                _state.value = UiState(loading = false, error = "无法读取密码数据，请重新解锁后重试")
            }
        }
    }

    private suspend fun buildReport(): HealthReport {
        val all = passwordRepository.healthCandidatesSkippingCorrupt()
        val withPassword = all.filter { it.passwordFingerprint != null }

        val weak = withPassword
            .filter { it.strengthScore < WEAK_SCORE_BELOW }
            .map { it.toEntry() }

        val reused = withPassword
            .groupBy { it.passwordFingerprint }
            .filterValues { it.size > 1 }
            .values
            .flatten()
            .map { it.toEntry() }

        val staleCutoff = System.currentTimeMillis() - STALE_DAYS * 24L * 60 * 60 * 1000
        val stale = withPassword
            .filter { it.updatedAt in 1 until staleCutoff }
            .map { it.toEntry() }

        return HealthReport(total = all.size, weak = weak, reused = reused, stale = stale)
    }

    private fun PasswordHealthCandidate.toEntry() =
        HealthEntry(id = id, title = title.ifBlank { "无标题" }, username = username)
}
