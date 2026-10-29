package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.repository.PasswordHealthCandidate
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.security.PasswordSecurityAnalyzer
import com.offlinevault.security.SecurityReport
import com.offlinevault.security.SessionManager
import com.offlinevault.data.preferences.SecurityPreferences
import com.offlinevault.security.CredentialType
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.SharingStarted
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
    private val passwordRepository: PasswordRepository,
    prefs: SecurityPreferences
) : ViewModel() {
    data class RecoveryStatus(val mnemonic: Boolean, val question: Boolean, val lastBackupAt: Long?, val credentialType: CredentialType)
    val recoveryStatus = combine(prefs.mnemonicEnabledFlow, prefs.recoveryQuestionFlow, prefs.lastBackupWrittenAtFlow, prefs.credentialTypeFlow) { words, question, backup, type ->
        RecoveryStatus(words, question.isNotBlank(), backup, CredentialType.fromKey(type))
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), RecoveryStatus(false, false, null, CredentialType.PASSWORD))

    data class HealthEntry(val id: String, val title: String, val username: String)

    data class HealthReport(
        val security: SecurityReport = SecurityReport.empty(),
        val weak: List<HealthEntry> = emptyList(),
        val reused: List<HealthEntry> = emptyList(),
        val stale: List<HealthEntry> = emptyList()
    ) {
        val total: Int get() = security.totalCredentials
    }

    data class UiState(
        val loading: Boolean = true,
        val error: String? = null,
        val report: HealthReport = HealthReport()
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()
    private var loadJob: Job? = null
    private val _initialRiskIds = MutableStateFlow<Set<String>?>(null)
    val initialRiskIds = _initialRiskIds.asStateFlow()

    init {
        viewModelScope.launch {
            SessionManager.unlocked.collect { unlocked ->
                if (!unlocked) {
                    loadJob?.cancel()
                    _initialRiskIds.value = null
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
                val generation = SessionManager.requireActiveSession()
                val report = withContext(Dispatchers.Default) { buildReport() }
                SessionManager.withActiveSessionNow(generation) {
                    if (_initialRiskIds.value == null) _initialRiskIds.value =
                        report.security.weakCredentialIds + report.security.reusedCredentialIds
                    _state.value = UiState(loading = false, report = report)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                _state.value = UiState(loading = false, error = "无法读取密码数据，请重新解锁后重试")
            }
        }
    }

    private suspend fun buildReport(): HealthReport {
        val all = passwordRepository.healthCandidatesSkippingCorrupt()
        val report = PasswordSecurityAnalyzer.analyze(all.map { it.toSecurityCandidate() })
        return HealthReport(
            security = report,
            weak = all.filter { it.id in report.weakCredentialIds }.map { it.toEntry() },
            reused = all.filter { it.id in report.reusedCredentialIds }.map { it.toEntry() },
            stale = all.filter { it.id in report.staleCredentialIds }.map { it.toEntry() }
        )
    }

    private fun PasswordHealthCandidate.toEntry() =
        HealthEntry(id = id, title = title.ifBlank { "无标题" }, username = username)
}
