package com.offlinevault.autofill

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.offlinevault.OfflineVaultApp
import com.offlinevault.R
import com.offlinevault.data.repository.DecryptedPassword
import com.offlinevault.security.SessionManager
import com.offlinevault.ui.components.SectionCard
import com.offlinevault.ui.theme.OfflineVaultTheme
import com.offlinevault.utils.ClipboardHelper
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class AutofillCandidate(
    val item: DecryptedPassword,
    val matchesTarget: Boolean
)

class AutofillSearchActivity : FragmentActivity() {

    private var backgroundedAt: Long = 0L
    private var autoLockJob: Job? = null

    // This activity can return an Autofill Dataset containing plaintext credentials. Keep the
    // timeout in memory so returning from background cannot race a coroutine/DataStore read and
    // allow a dataset to be selected after the configured lock deadline.
    @Volatile
    private var autoLockSeconds = 0
    private var returningDataset = false

    companion object {
        private const val EXTRA_USERNAME_ID = "autofill_username_id"
        private const val EXTRA_PASSWORD_ID = "autofill_password_id"
        private const val EXTRA_WEB_DOMAIN = "autofill_web_domain"
        private const val EXTRA_PACKAGE_NAME = "autofill_package_name"

        fun buildIntent(
            context: Context,
            usernameId: android.view.autofill.AutofillId?,
            passwordId: android.view.autofill.AutofillId?,
            webDomain: String?,
            packageName: String?
        ): Intent = Intent(context, AutofillSearchActivity::class.java).apply {
            putExtra(EXTRA_WEB_DOMAIN, webDomain)
            putExtra(EXTRA_PACKAGE_NAME, packageName)
            putExtra(EXTRA_USERNAME_ID, usernameId)
            putExtra(EXTRA_PASSWORD_ID, passwordId)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val usernameId = intent.autofillIdExtra(EXTRA_USERNAME_ID)
        val passwordId = intent.autofillIdExtra(EXTRA_PASSWORD_ID)
        val webDomain = intent.getStringExtra(EXTRA_WEB_DOMAIN)
        val packageName = intent.getStringExtra(EXTRA_PACKAGE_NAME)
        val targetLabel = OriginMatcher.targetLabel(webDomain, packageName)

        if (!SessionManager.isUnlocked || (usernameId == null && passwordId == null)) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        val app = application as OfflineVaultApp
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                app.container.securityPreferences.autoLockSecondsFlow.collect {
                    autoLockSeconds = it
                }
            }
        }
        val loadingState = mutableStateOf(true)
        val errorState = mutableStateOf<String?>(null)
        val itemsState = mutableStateOf<List<AutofillCandidate>>(emptyList())
        var candidatesGeneration: Long? = null
        val allCandidatesLoaded = mutableStateOf(false)

        fun cancelForLockedSession() {
            // This screen can contain fully decrypted credentials. Drop the Compose state before
            // finishing so a lock/background transition never leaves a stale frame or an in-memory
            // candidate list behind while the activity is being torn down.
            loadingState.value = false
            errorState.value = null
            allCandidatesLoaded.value = false
            itemsState.value = emptyList()
            candidatesGeneration = null
            setResult(RESULT_CANCELED)
            finish()
        }

        // MainActivity's lifecycle is not active while this authentication activity is on top.
        // Observe the session here as well so an explicit lock, screen-off lock or memory-pressure
        // lock immediately closes the manual picker and clears its decrypted candidates.
        lifecycleScope.launch {
            SessionManager.unlocked.collect { unlocked ->
                if (!unlocked && !returningDataset) cancelForLockedSession()
            }
        }

        fun matchesCurrentTarget(url: String): Boolean =
            (!webDomain.isNullOrBlank() && OriginMatcher.matches(url, webDomain)) ||
                (!packageName.isNullOrBlank() && OriginMatcher.matchesApp(url, packageName))

        fun loadCandidates(includeAll: Boolean) {
            if (includeAll && allCandidatesLoaded.value) return
            loadingState.value = true
            errorState.value = null
            lifecycleScope.launch {
                val expectedGeneration = try {
                    SessionManager.requireActiveSession()
                } catch (_: Exception) {
                    cancelForLockedSession()
                    return@launch
                }
                val result = withContext(Dispatchers.IO) {
                    try {
                        if (includeAll) {
                            app.container.passwordRepository.allDecryptedSkippingCorrupt().map { candidate ->
                                AutofillCandidate(candidate, matchesCurrentTarget(candidate.url))
                            }.sortedByDescending { it.matchesTarget }
                        } else {
                            // Do not decrypt unrelated credentials merely to present the default
                            // autofill list. The broader list is loaded only after explicit user
                            // confirmation in the sensitive activity.
                            app.container.passwordRepository.decryptedMatching(::matchesCurrentTarget)
                                .map { AutofillCandidate(it, matchesTarget = true) }
                        }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        null
                    }
                }
                val published = try {
                    // Do not let a result decrypted under a previous session appear after a fast
                    // lock/unlock transition. State publication is inside the gate as well.
                    SessionManager.withActiveSessionNow(expectedGeneration) {
                        if (isFinishing || isDestroyed) {
                            false
                        } else {
                            loadingState.value = false
                            if (result == null) {
                                errorState.value = "无法读取密码库"
                            } else {
                                itemsState.value = result
                                candidatesGeneration = expectedGeneration
                                if (includeAll) allCandidatesLoaded.value = true
                            }
                            true
                        }
                    }
                } catch (_: Exception) {
                    false
                }
                if (!published) {
                    cancelForLockedSession()
                }
            }
        }
        loadCandidates(includeAll = false)

        setContent {
            OfflineVaultTheme {
                AutofillSearchScreen(
                    targetLabel = targetLabel,
                    loading = loadingState.value,
                    error = errorState.value,
                    candidates = itemsState.value,
                    allCandidatesLoaded = allCandidatesLoaded.value,
                    confirmMatchedWebFill = !webDomain.isNullOrBlank(),
                    onRequestAllCandidates = { loadCandidates(includeAll = true) },
                    onBack = { finish() },
                    onPick = { item ->
                        if (returningDataset) return@AutofillSearchScreen
                        returningDataset = true
                        lifecycleScope.launch {
                            val committed = try {
                                // The Dataset contains plaintext. Keep dataset construction and the
                                // platform handoff in one active-session operation so lock() cannot
                                // invalidate the session between a last check and setResult().
                                val expectedGeneration = candidatesGeneration
                                    ?: throw com.offlinevault.security.VaultLockedException("No active candidates")
                                SessionManager.withActiveSessionNow(expectedGeneration) {
                                    if (isFinishing || isDestroyed) {
                                        false
                                    } else {
                                        val dataset = buildResultDataset(
                                            item,
                                            usernameId,
                                            passwordId,
                                            targetLabel
                                        )
                                        val resultIntent = Intent().putExtra(
                                            AutofillManager.EXTRA_AUTHENTICATION_RESULT,
                                            dataset
                                        )
                                        SessionManager.requireActiveSession(expectedGeneration)
                                        setResult(RESULT_OK, resultIntent)
                                        true
                                    }
                                }
                            } catch (_: Exception) {
                                false
                            }
                            if (committed) {
                                finish()
                            } else {
                                returningDataset = false
                                cancelForLockedSession()
                            }
                        }
                    }
                )
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (isChangingConfigurations) {
            backgroundedAt = 0L
            return
        }
        backgroundedAt = System.currentTimeMillis()
        scheduleAutoLock()
    }

    override fun onStart() {
        super.onStart()
        autoLockJob?.cancel()
        autoLockJob = null
        ClipboardHelper.restorePendingSensitiveClear(applicationContext)
        if (!SessionManager.isUnlocked || backgroundedAt == 0L) return
        val seconds = autoLockSeconds
        if (seconds == 0 || System.currentTimeMillis() - backgroundedAt >= seconds * 1000L) {
            SessionManager.lock()
        }
    }

    private fun scheduleAutoLock() {
        autoLockJob?.cancel()
        val seconds = autoLockSeconds
        if (seconds <= 0) {
            SessionManager.lock()
            return
        }
        autoLockJob = lifecycleScope.launch {
            delay(seconds * 1000L)
            SessionManager.lock()
        }
    }

    private fun buildResultDataset(
        item: DecryptedPassword,
        usernameId: AutofillId?,
        passwordId: AutofillId?,
        targetLabel: String
    ): Dataset {
        val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_title, item.title.ifEmpty { "离线密码库" })
            setTextViewText(
                R.id.autofill_subtitle,
                listOf(item.username.ifEmpty { item.url }, "当前：$targetLabel")
                    .filter { it.isNotBlank() }
                    .joinToString(" · ")
            )
        }
        return Dataset.Builder(presentation).apply {
            usernameId?.let { setValue(it, AutofillValue.forText(item.username)) }
            passwordId?.let { setValue(it, AutofillValue.forText(item.password)) }
        }.build()
    }

    @Suppress("DEPRECATION")
    private fun Intent.autofillIdExtra(key: String): AutofillId? =
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                getParcelableExtra(key, AutofillId::class.java)
            } else {
                getParcelableExtra(key)
            }
        }.getOrNull()
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
private fun AutofillSearchScreen(
    targetLabel: String,
    loading: Boolean,
    error: String?,
    candidates: List<AutofillCandidate>,
    allCandidatesLoaded: Boolean,
    confirmMatchedWebFill: Boolean,
    onRequestAllCandidates: () -> Unit,
    onBack: () -> Unit,
    onPick: (DecryptedPassword) -> Unit
) {
    var query by remember { mutableStateOf("") }
    var showAll by remember { mutableStateOf(false) }
    var showAllConfirmation by remember { mutableStateOf(false) }
    var pendingNonMatching by remember { mutableStateOf<AutofillCandidate?>(null) }
    var pendingWebMatch by remember { mutableStateOf<AutofillCandidate?>(null) }
    val visibleCandidates = if (showAll && allCandidatesLoaded) candidates else candidates.filter { it.matchesTarget }
    val filtered = remember(query, visibleCandidates) {
        val keyword = query.trim()
        if (keyword.isBlank()) visibleCandidates
        else visibleCandidates.filter { candidate ->
            val item = candidate.item
            item.title.contains(keyword, ignoreCase = true) ||
                item.username.contains(keyword, ignoreCase = true) ||
                item.url.contains(keyword, ignoreCase = true)
        }
    }

    Scaffold(
        containerColor = androidx.compose.ui.graphics.Color.Transparent,
        snackbarHost = { SnackbarHost(remember { SnackbarHostState() }) },
        topBar = {
            TopAppBar(
                title = { Text("自动填充手动搜索", fontWeight = FontWeight.Bold) },
                actions = { TextButton(onClick = onBack) { Text("关闭") } },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = androidx.compose.ui.graphics.Color.Transparent,
                    titleContentColor = MaterialTheme.colorScheme.onBackground
                )
            )
        }
    ) { padding ->
        if (loading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            }
            return@Scaffold
        }

        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            Text(
                "当前目标：$targetLabel",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (!showAll) {
                Text(
                    "仅显示与当前网站或应用精确匹配的账号。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                TextButton(onClick = { showAllConfirmation = true }) {
                    Text("手动查看其他密码库项目")
                }
            } else {
                Text(
                    "正在显示全部项目。填充不匹配项目时将再次确认。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("搜索标题、用户名或网址") },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline
                )
            )
            Spacer(Modifier.height(12.dp))
            when {
                error != null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(error, color = MaterialTheme.colorScheme.error)
                }

                filtered.isEmpty() -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        if (showAll) "没有匹配的密码项" else "没有与当前目标匹配的密码项",
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                else -> LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items(filtered, key = { it.item.id }) { candidate ->
                        val item = candidate.item
                        SectionCard {
                            Column(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        when {
                                            !candidate.matchesTarget -> pendingNonMatching = candidate
                                            confirmMatchedWebFill -> pendingWebMatch = candidate
                                            else -> onPick(item)
                                        }
                                    }
                                    .padding(vertical = 8.dp)
                            ) {
                                Text(item.title.ifEmpty { "未命名项目" }, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
                                Text(
                                    listOf(item.username.ifEmpty { item.url }, item.url.takeIf { item.url.isNotBlank() && item.url != item.username }.orEmpty())
                                        .filter { it.isNotBlank() }
                                        .joinToString(" · "),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showAllConfirmation) {
        AlertDialog(
            onDismissRequest = { showAllConfirmation = false },
            title = { Text("查看全部项目？") },
            text = { Text("当前网站或应用的身份由系统自动填充框架提供，无法由本应用独立验证。只应在确认目标可信时手动选择其他项目。") },
            confirmButton = {
                TextButton(onClick = {
                    showAllConfirmation = false
                    showAll = true
                    onRequestAllCandidates()
                }) { Text("继续查看") }
            },
            dismissButton = { TextButton(onClick = { showAllConfirmation = false }) { Text("取消") } }
        )
    }

    pendingNonMatching?.let { candidate ->
        AlertDialog(
            onDismissRequest = { pendingNonMatching = null },
            title = { Text("确认填充到当前目标？") },
            text = {
                Text(
                    "“${candidate.item.title.ifBlank { "未命名项目" }}”与当前目标“$targetLabel”不匹配。确认后，其账号和密码将填写到当前页面。"
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingNonMatching = null
                    onPick(candidate.item)
                }) { Text("确认填充") }
            },
            dismissButton = { TextButton(onClick = { pendingNonMatching = null }) { Text("取消") } }
        )
    }

    pendingWebMatch?.let { candidate ->
        AlertDialog(
            onDismissRequest = { pendingWebMatch = null },
            title = { Text("确认网站填充？") },
            text = {
                Text(
                    "系统报告的目标是“$targetLabel”。网页域名由发起自动填充的应用提供，" +
                        "请同时确认域名与请求应用可信，再填充“${candidate.item.title.ifBlank { "未命名项目" }}”。"
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingWebMatch = null
                    onPick(candidate.item)
                }) { Text("确认填充") }
            },
            dismissButton = { TextButton(onClick = { pendingWebMatch = null }) { Text("取消") } }
        )
    }
}
