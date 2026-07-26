package com.offlinevault.ui.screens

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.offlinevault.BuildConfig
import com.offlinevault.data.backup.ImportPreview
import com.offlinevault.data.backup.ImportResult
import com.offlinevault.security.MnemonicManager
import com.offlinevault.security.PasswordStrengthChecker
import com.offlinevault.security.SessionManager
import com.offlinevault.ui.components.ImportPreviewDialog
import com.offlinevault.ui.components.PasteImportDialog
import com.offlinevault.ui.components.PasswordVisualField
import com.offlinevault.ui.components.SectionCard
import com.offlinevault.ui.components.SecureWindowEffect
import com.offlinevault.ui.components.VaultTextField
import com.offlinevault.utils.FileIo
import com.offlinevault.utils.FilePickerCompat
import com.offlinevault.utils.Formatters
import com.offlinevault.utils.ImportFormatDetector
import com.offlinevault.utils.toUserMessage
import com.offlinevault.viewmodel.SettingsViewModel
import kotlinx.coroutines.launch
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    biometricAvailable: Boolean,
    onBack: () -> Unit,
    onEnableBiometric: (onDone: (Boolean) -> Unit) -> Unit,
    onOpenTrash: () -> Unit = {},
    onOpenHealth: () -> Unit = {}
) {
    val context = LocalContext.current
    val appName = stringResource(com.offlinevault.R.string.app_name)
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    val biometricEnabled by viewModel.biometricEnabled.collectAsStateWithLifecycle()
    val autoLock by viewModel.autoLockSeconds.collectAsStateWithLifecycle()
    val screenshotBlocked by viewModel.screenshotBlocked.collectAsStateWithLifecycle()
    val lockOnScreenOff by viewModel.lockOnScreenOff.collectAsStateWithLifecycle()
    val healthCheckEnabled by viewModel.healthCheckEnabled.collectAsStateWithLifecycle()
    val clipboardSeconds by viewModel.clipboardClearSeconds.collectAsStateWithLifecycle()
    val recoveryQuestion by viewModel.recoveryQuestion.collectAsStateWithLifecycle()
    val mnemonicEnabled by viewModel.mnemonicEnabled.collectAsStateWithLifecycle()
    val credentialType by viewModel.credentialType.collectAsStateWithLifecycle()
    val vaults by viewModel.vaults.collectAsStateWithLifecycle()
    val mnemonicManager = remember { MnemonicManager() }

    fun toast(msg: String) = scope.launch { snackbar.showSnackbar(msg) }
    fun importToast(r: ImportResult) = toast(r.toUserMessage())

    // ---- Dialog state ----
    var showAutoLock by remember { mutableStateOf(false) }
    var showClipboard by remember { mutableStateOf(false) }
    var showChangeMaster by remember { mutableStateOf(false) }
    var showChangeRecovery by remember { mutableStateOf(false) }
    var showMnemonicPasswordPrompt by remember { mutableStateOf(false) }
    var showDisableMnemonicPrompt by remember { mutableStateOf(false) }
    var showCsvWarning by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    var pendingMnemonicWords by remember { mutableStateOf<List<String>?>(null) }
    var pendingMnemonicError by remember { mutableStateOf<String?>(null) }
    var pendingMnemonicSaving by remember { mutableStateOf(false) }
    var verifyingMnemonicMaster by remember { mutableStateOf(false) }

    // A regenerated phrase is just as sensitive as the first-run phrase. Force screenshot
    // protection while it is visible even if the user disabled the general screen setting.
    SecureWindowEffect(enabled = pendingMnemonicWords != null)

    // Pending values across file picker round-trips.
    var pendingJsonBackup by remember { mutableStateOf<String?>(null) }
    var pendingCsvVaultId by remember { mutableStateOf<String?>(null) }
    var importPasswordPrompt by remember { mutableStateOf(false) }
    var pendingImportJson by remember { mutableStateOf<String?>(null) }
    var pendingImportCsv by remember { mutableStateOf<String?>(null) }
    var pendingImportAction by remember { mutableStateOf<SettingsPendingImportAction?>(null) }
    var pendingImportPreview by remember { mutableStateOf<ImportPreview?>(null) }
    var csvImportTargetPick by remember { mutableStateOf(false) }
    var csvExportTargetPick by remember { mutableStateOf(false) }
    var showPasteImport by remember { mutableStateOf(false) }
    var askExportPassword by remember { mutableStateOf(false) }
    var csvFormatPick by remember { mutableStateOf(false) }
    // Chosen CSV export shape: true = slim browser-compatible (name,url,username,password).
    var pendingCsvSlim by remember { mutableStateOf(false) }

    // ---- File launchers ----
    val saveJsonLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        com.offlinevault.security.LockGuard.suppressNextBackground = false
        val json = pendingJsonBackup
        if (uri != null && json != null && SessionManager.isUnlocked) {
            scope.launch {
                val ok = FileIo.writeText(context, uri, json)
                toast(if (ok) "加密备份已保存" else "无法写入文件")
            }
        } else if (uri != null && json != null) {
            toast("密码库已锁定，请解锁后重新导出")
        }
        pendingJsonBackup = null
    }

    val saveCsvLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/csv")
    ) { uri ->
        com.offlinevault.security.LockGuard.suppressNextBackground = false
        val vaultId = pendingCsvVaultId
        if (uri != null && vaultId != null && SessionManager.isUnlocked) {
            viewModel.buildCsv(vaultId, pendingCsvSlim) { result ->
                val csv = result.content
                if (csv == null) {
                    result.errorMessage?.let(::toast)
                    return@buildCsv
                }
                scope.launch {
                    val ok = FileIo.writeText(context, uri, csv)
                    toast(if (ok) "CSV 已导出（包含明文密码）" else "无法写入文件")
                }
            }
        } else if (uri != null && vaultId != null) {
            toast("密码库已锁定，请解锁后重新导出")
        }
        pendingCsvVaultId = null
    }

    fun previewCsvImport(text: String, vaultId: String) {
        viewModel.previewCsvImport(text, vaultId) { result ->
            val preview = result.preview
            if (preview != null) {
                pendingImportAction = SettingsPendingImportAction.Csv(text, vaultId)
                pendingImportPreview = preview
            } else {
                toast(result.errorMessage ?: "无法预览 CSV")
            }
        }
    }

    fun handleImportText(text: String, sourceName: String = "") {
        if (text.isBlank()) {
            toast("导入内容为空")
            return
        }
        if (!FileIo.isTextWithinImportLimit(text)) {
            toast("导入内容超过 10 MB 限制")
            return
        }
        if (ImportFormatDetector.looksLikeCsv(sourceName, text)) {
            if (vaults.isEmpty()) {
                previewCsvImport(text, "")
            } else {
                pendingImportCsv = text
                csvImportTargetPick = true
            }
        } else {
            pendingImportJson = text
            importPasswordPrompt = true
        }
    }

    fun previewJsonImport(text: String, password: String) {
        viewModel.previewJsonImport(text, password) { result ->
            val preview = result.preview
            if (preview != null) {
                pendingImportAction = SettingsPendingImportAction.Json(text, password)
                pendingImportPreview = preview
            } else {
                toast(result.errorMessage ?: "无法预览备份")
            }
        }
    }

    fun executePendingImport(strategy: com.offlinevault.data.backup.ImportConflictStrategy) {
        when (val action = pendingImportAction) {
            is SettingsPendingImportAction.Csv -> {
                viewModel.importCsv(action.content, action.vaultId, strategy) { importToast(it) }
            }
            is SettingsPendingImportAction.Json -> {
                viewModel.importJson(action.content, action.password, strategy) { importToast(it) }
            }
            null -> Unit
        }
        pendingImportAction = null
        pendingImportPreview = null
    }

    fun handlePickedUri(uri: Uri?) {
        com.offlinevault.security.LockGuard.suppressNextBackground = false
        if (uri == null) return
        // A system picker may have exceeded the configured auto-lock timeout. Refuse rather than
        // retaining the selected backup or operating with a cleared session key.
        if (!SessionManager.isUnlocked) {
            toast("密码库已锁定，请解锁后重新导入")
            return
        }
        FilePickerCompat.persistReadPermission(context, uri)
        scope.launch {
            val text = FileIo.readText(context, uri)
            if (text == null) {
                toast("无法读取文件，或文件超过 10 MB")
                return@launch
            }
            handleImportText(text, uri.toString())
        }
    }

    // Storage Access Framework picker (system DocumentsUI). Available on every Android 8.0+ device,
    // no third-party file manager required.
    val openDocumentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        handlePickedUri(uri)
    }

    // Fallback for stripped ROMs that lack DocumentsUI: ACTION_GET_CONTENT.
    val getContentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        handlePickedUri(FilePickerCompat.extractUri(result.data))
    }

    fun launchImport() {
        com.offlinevault.security.LockGuard.suppressNextBackground = true
        // Try three pickers in order, catching ALL exceptions each time (some ROMs throw
        // SecurityException/RuntimeException rather than ActivityNotFoundException):
        //   1. SAF OpenDocument (system DocumentsUI) — present on every stock Android 8.0+.
        //   2. ACTION_GET_CONTENT via system chooser.
        //   3. ACTION_GET_CONTENT directly (no chooser) — for ROMs whose chooser itself refuses.
        try {
            openDocumentLauncher.launch(FilePickerCompat.importMimeTypes)
            return
        } catch (_: Exception) {
            // DocumentsUI unavailable/blocked.
        }
        try {
            getContentLauncher.launch(FilePickerCompat.createFallbackImportChooser())
            return
        } catch (_: Exception) {
        }
        try {
            getContentLauncher.launch(FilePickerCompat.createDirectGetContentIntent())
            return
        } catch (_: Exception) {
        }
        com.offlinevault.security.LockGuard.suppressNextBackground = false
        showPasteImport = true
        toast("文件选择器不可用，已打开粘贴导入")
    }

    fun launchCsvSave(vaultId: String) {
        pendingCsvVaultId = vaultId
        com.offlinevault.security.LockGuard.suppressNextBackground = true
        try {
            saveCsvLauncher.launch("offline-vault-export-${Formatters.fileStamp()}.csv")
        } catch (_: Exception) {
            com.offlinevault.security.LockGuard.suppressNextBackground = false
            pendingCsvVaultId = null
            toast("未找到可用的文件管理器，无法导出")
        }
    }

    // ---- Autofill enablement ----
    val autofillManager = remember { context.getSystemService(AutofillManager::class.java) }
    val autofillSupported = remember {
        runCatching { autofillManager?.isAutofillSupported == true }.getOrDefault(false)
    }
    var autofillServiceEnabled by remember {
        mutableStateOf(runCatching { autofillManager?.hasEnabledAutofillServices() == true }.getOrDefault(false))
    }
    val autofillSettingsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        com.offlinevault.security.LockGuard.suppressNextBackground = false
        autofillServiceEnabled =
            runCatching { autofillManager?.hasEnabledAutofillServices() == true }.getOrDefault(false)
    }
    fun openAutofillSettings() {
        com.offlinevault.security.LockGuard.suppressNextBackground = true
        // Try, in order: the autofill-service picker scoped to us, the generic autofill picker,
        // then this app's details page. Some ROMs throw SecurityException/RuntimeException (not
        // ActivityNotFoundException) for the autofill intents, so every attempt must catch broadly
        // or the app crashes when the system refuses the intent.
        val candidates = listOf(
            Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                .setData(Uri.parse("package:${context.packageName}")),
            Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE),
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(Uri.parse("package:${context.packageName}"))
        )
        for (intent in candidates) {
            try {
                autofillSettingsLauncher.launch(intent)
                return
            } catch (_: Exception) {
                // Intent unsupported or blocked on this ROM — try the next one.
            }
        }
        com.offlinevault.security.LockGuard.suppressNextBackground = false
        toast("无法打开自动填充设置，请在系统设置中手动开启")
    }

    Scaffold(
        containerColor = androidx.compose.ui.graphics.Color.Transparent,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("设置", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = androidx.compose.ui.graphics.Color.Transparent,
                    titleContentColor = MaterialTheme.colorScheme.onBackground
                )
            )
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            SectionHeader("安全")
            SectionCard {
                Column {
                    if (biometricAvailable) {
                        ToggleSetting(
                            title = "指纹解锁",
                            subtitle = "使用生物识别解锁",
                            checked = biometricEnabled,
                            onChange = { enabled ->
                                if (enabled) {
                                    onEnableBiometric { ok ->
                                        toast(if (ok) "已启用指纹解锁" else "无法启用指纹解锁")
                                    }
                                } else {
                                    viewModel.disableBiometric { ok ->
                                        toast(if (ok) "已关闭指纹解锁" else "无法关闭指纹解锁")
                                    }
                                }
                            }
                        )
                        SettingDivider()
                    }
                    ToggleSetting(
                        title = "禁止截屏和录屏",
                        subtitle = if (screenshotBlocked) "已开启，当前界面无法被捕获"
                        else "已关闭，允许截屏",
                        checked = screenshotBlocked,
                        onChange = {
                            viewModel.setScreenshotBlocked(it) { ok ->
                                toast(
                                    if (!ok) "设置失败"
                                    else if (it) "已禁止截屏和录屏"
                                    else "警告：当前允许截屏"
                                )
                            }
                        }
                    )
                    SettingDivider()
                    ClickSetting("自动锁定", autoLockLabel(autoLock)) { showAutoLock = true }
                    SettingDivider()
                    ToggleSetting(
                        title = "锁屏时立即锁定",
                        subtitle = "屏幕关闭后立刻锁定密码库，不等待自动锁定时间",
                        checked = lockOnScreenOff,
                        onChange = { enabled ->
                            viewModel.setLockOnScreenOff(enabled) { ok -> if (!ok) toast("设置失败") }
                        }
                    )
                    SettingDivider()
                    ClickSetting(
                        "自动清除剪贴板",
                        "${clipboardSeconds}秒"
                    ) { showClipboard = true }
                    SettingDivider()
                    ClickSetting("修改${credentialType.noun}", credentialType.displayName) { showChangeMaster = true }
                    SettingDivider()
                    ClickSetting("安全问题", recoveryQuestion.ifBlank { "未设置" }) { showChangeRecovery = true }
                    SettingDivider()
                    Column(Modifier.fillMaxWidth().padding(vertical = 12.dp)) {
                        Text("助记词与恢复", style = MaterialTheme.typography.bodyLarge)
                        Text(
                            if (mnemonicEnabled) "已启用 12 个助记词恢复，仅用于最终恢复"
                            else "未启用 12 个助记词恢复",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(onClick = { showMnemonicPasswordPrompt = true }) {
                                Text(if (mnemonicEnabled) "重新生成" else "启用")
                            }
                            if (mnemonicEnabled) {
                                TextButton(onClick = { showDisableMnemonicPrompt = true }) {
                                    Text("关闭", color = MaterialTheme.colorScheme.error)
                                }
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(20.dp))
            SectionHeader("自动填充")
            SectionCard {
                Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Text("在其他应用和网页中自动填充与保存账号密码", style = MaterialTheme.typography.bodyLarge)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        when {
                            !autofillSupported -> "当前设备不支持系统自动填充"
                            autofillServiceEnabled -> "已将本应用设为系统自动填充服务"
                            else -> "尚未启用：需在系统设置中将「$appName」设为自动填充服务后才能使用"
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (autofillServiceEnabled || !autofillSupported)
                            MaterialTheme.colorScheme.onSurfaceVariant
                        else MaterialTheme.colorScheme.error
                    )
                    if (autofillSupported) {
                        Spacer(Modifier.height(8.dp))
                        TextButton(onClick = { openAutofillSettings() }) {
                            Text(if (autofillServiceEnabled) "重新打开系统设置" else "去系统设置开启")
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "开启步骤：点击上方按钮 → 选择 $appName → 返回本应用。若按钮打不开，请手动进入「系统设置 → 系统 → 语言和输入法 → 自动填充服务」选择 $appName。",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "使用时，在浏览器或其他 App 的账号/密码输入框中点击，系统会显示 Offline Vault 的填充建议。",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            Spacer(Modifier.height(20.dp))
            SectionHeader("工具")
            SectionCard {
                Column {
                    ToggleSetting(
                        title = "密码安全体检",
                        subtitle = "检查弱密码、重复使用和长期未更新；关闭后不再显示",
                        checked = healthCheckEnabled,
                        onChange = { enabled ->
                            viewModel.setHealthCheckEnabled(enabled) { ok -> if (!ok) toast("设置失败") }
                        }
                    )
                    if (healthCheckEnabled) {
                        SettingDivider()
                        ClickSetting("查看体检报告", "弱密码、重复使用、长期未更新") { onOpenHealth() }
                    }
                    SettingDivider()
                    ClickSetting("回收站", "已删除的密码可在此恢复") { onOpenTrash() }
                }
            }

            Spacer(Modifier.height(20.dp))
            SectionHeader("备份与数据")
            SectionCard {
                Column {
                    ClickSetting("导出加密备份（JSON）", "推荐") { askExportPassword = true }
                    SettingDivider()
                    ClickSetting("导出表格（CSV）", "明文格式，请谨慎使用") { showCsvWarning = true }
                    SettingDivider()
                    ClickSetting("导入（加密备份 / 浏览器 CSV）", "") { launchImport() }
                    SettingDivider()
                    ClickSetting("粘贴导入 JSON/CSV", "文件选择器不可用时使用") { showPasteImport = true }
                }
            }

            Spacer(Modifier.height(20.dp))
            SectionHeader("关于")
            SectionCard {
                Column {
                    ClickSetting("检查更新", "通过 GitHub Releases 获取新版") {
                        val intent = Intent(
                            Intent.ACTION_VIEW,
                            Uri.parse("https://github.com/koajsj/vault/releases/latest")
                        )
                        try {
                            context.startActivity(intent)
                        } catch (_: ActivityNotFoundException) {
                            toast("未找到可打开更新页面的浏览器")
                        } catch (_: Exception) {
                            toast("无法打开更新页面")
                        }
                    }
                    SettingDivider()
                    ClickSetting(
                        "关于离线密码库",
                        "版本 ${BuildConfig.VERSION_NAME} · 完全离线"
                    ) { showAbout = true }
                }
            }
            Spacer(Modifier.height(28.dp))
        }
    }

    // ---- Auto-lock dialog ----
    if (showAutoLock) {
        ChoiceDialog(
            title = "自动锁定",
            options = listOf(
                0 to "立即锁定",
                30 to "30 秒后",
                60 to "1 分钟后",
                300 to "5 分钟后",
                600 to "10 分钟后",
                1800 to "30 分钟后"
            ),
            selected = autoLock,
            onSelect = {
                viewModel.setAutoLockSeconds(it) { ok -> if (!ok) toast("设置失败") }
                showAutoLock = false
            },
            onDismiss = { showAutoLock = false }
        )
    }
    if (showClipboard) {
        ChoiceDialog(
            title = "自动清除剪贴板",
            options = listOf(10 to "10 秒", 20 to "20 秒", 30 to "30 秒", 60 to "60 秒"),
            selected = clipboardSeconds,
            onSelect = {
                viewModel.setClipboardSeconds(it) { ok -> if (!ok) toast("设置失败") }
                showClipboard = false
            },
            onDismiss = { showClipboard = false }
        )
    }

    // ---- Change master password ----
    if (showChangeMaster) {
        ChangeMasterDialog(
            credentialType = credentialType,
            onDismiss = { showChangeMaster = false },
            onConfirm = { old, new ->
                viewModel.changeMasterPassword(old, new) { ok, msg ->
                    if (ok) { showChangeMaster = false; toast("${credentialType.noun}已修改") }
                    else toast(msg ?: "操作失败")
                }
            }
        )
    }

    // ---- Change recovery ----
    if (showChangeRecovery) {
        ChangeRecoveryDialog(
            currentQuestion = recoveryQuestion,
            onDismiss = { showChangeRecovery = false },
            onConfirm = { q, a ->
                viewModel.changeRecovery(q, a) { ok, msg ->
                    if (ok) {
                        showChangeRecovery = false
                        toast("安全问题已更新")
                    } else {
                        toast(msg ?: "操作失败")
                    }
                }
            }
        )
    }

    if (showMnemonicPasswordPrompt) {
        MasterPasswordDialog(
            title = if (mnemonicEnabled) "重新生成助记词" else "启用助记词恢复",
            message = if (mnemonicEnabled)
                "请输入当前主密码。新助记词生效后，旧助记词将立即失效。"
            else
                "请输入当前主密码后生成新的 12 个助记词。助记词不会明文保存，只展示一次。",
            confirmLabel = "继续",
            credentialType = credentialType,
            onDismiss = { if (!verifyingMnemonicMaster) showMnemonicPasswordPrompt = false },
            onConfirm = { masterPassword ->
                if (!verifyingMnemonicMaster) {
                    verifyingMnemonicMaster = true
                    viewModel.authorizeMnemonicRecoveryUpdate(masterPassword) { ok, msg ->
                        verifyingMnemonicMaster = false
                        if (ok) {
                            pendingMnemonicWords = mnemonicManager.generateWords()
                            pendingMnemonicError = null
                            pendingMnemonicSaving = false
                            showMnemonicPasswordPrompt = false
                        } else {
                            toast(msg ?: "当前密码不正确")
                        }
                    }
                }
            }
        )
    }

    if (pendingMnemonicWords != null) {
        AlertDialog(
            onDismissRequest = {
                if (!pendingMnemonicSaving) {
                    pendingMnemonicWords = null
                    pendingMnemonicError = null
                }
            },
            title = { Text(if (mnemonicEnabled) "重新生成助记词" else "启用助记词恢复") },
            text = {
                MnemonicConfirmationContent(
                    words = pendingMnemonicWords!!,
                    actionLabel = when {
                        pendingMnemonicSaving -> "正在启用…"
                        mnemonicEnabled -> "启用新助记词"
                        else -> "启用助记词恢复"
                    },
                    enabled = !pendingMnemonicSaving,
                    errorMessage = pendingMnemonicError,
                    onBack = {
                        if (!pendingMnemonicSaving) {
                            pendingMnemonicWords = null
                            pendingMnemonicError = null
                        }
                    },
                    onConfirm = {
                        val phrase = pendingMnemonicWords?.joinToString(" ")
                        if (phrase != null) {
                            val replacingExistingMnemonic = mnemonicEnabled
                            pendingMnemonicSaving = true
                            viewModel.updateMnemonicRecoveryForUnlockedSession(phrase) { ok, msg ->
                                pendingMnemonicSaving = false
                                if (ok) {
                                    pendingMnemonicWords = null
                                    pendingMnemonicError = null
                                    toast(
                                        if (replacingExistingMnemonic) "助记词已重新生成，旧助记词已失效"
                                        else "助记词恢复已启用"
                                    )
                                } else {
                                    pendingMnemonicError = "${msg ?: "操作失败"}；此助记词尚未启用"
                                }
                            }
                        }
                    }
                )
            },
            confirmButton = {},
            dismissButton = {}
        )
    }

    if (showDisableMnemonicPrompt) {
        MasterPasswordDialog(
            title = "关闭助记词恢复",
            message = "请输入当前主密码。关闭后将删除助记词恢复材料，仅保留主密码 / 指纹 / 密保问题恢复。",
            confirmLabel = "关闭",
            credentialType = credentialType,
            onDismiss = { showDisableMnemonicPrompt = false },
            onConfirm = { masterPassword ->
                showDisableMnemonicPrompt = false
                viewModel.disableMnemonicRecovery(masterPassword) { ok, msg ->
                    toast(if (ok) "已关闭助记词恢复" else (msg ?: "操作失败"))
                }
            }
        )
    }

    // ---- Export JSON: ask password ----
    if (askExportPassword) {
        BackupPasswordDialog(
            title = "备份密码",
            message = "该密码用于加密备份文件，恢复数据时需要输入。",
            onDismiss = { askExportPassword = false },
            onConfirm = { pw ->
                askExportPassword = false
                viewModel.buildEncryptedJsonBackup(pw) { result ->
                    val json = result.content
                    if (json == null) {
                        result.errorMessage?.let(::toast)
                        return@buildEncryptedJsonBackup
                    }
                    if (result.validated) {
                        toast("备份已通过校验，请选择保存位置")
                    }
                    pendingJsonBackup = json
                    com.offlinevault.security.LockGuard.suppressNextBackground = true
                    try {
                        saveJsonLauncher.launch("offline-vault-backup-${Formatters.fileStamp()}.json")
                    } catch (_: Exception) {
                        com.offlinevault.security.LockGuard.suppressNextBackground = false
                        pendingJsonBackup = null
                        toast("未找到可用的文件管理器，无法保存备份")
                    }
                }
            }
        )
    }

    // ---- CSV warning then vault pick ----
    if (showCsvWarning) {
        AlertDialog(
            onDismissRequest = { showCsvWarning = false },
            icon = { Icon(Icons.Filled.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("导出明文 CSV？") },
            text = { Text("CSV 文件将包含明文密码，任何能打开文件的人都可以查看。请仅导出到可信且安全的位置。") },
            confirmButton = {
                TextButton(onClick = {
                    showCsvWarning = false
                    if (vaults.isEmpty()) toast("没有可导出的密码库") else csvFormatPick = true
                }) { Text("我已了解，继续导出", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { showCsvWarning = false }) { Text("取消") } }
        )
    }

    // ---- CSV export: choose format ----
    if (csvFormatPick) {
        fun proceed(slim: Boolean) {
            pendingCsvSlim = slim
            csvFormatPick = false
            if (vaults.size == 1) launchCsvSave(vaults.first().id) else csvExportTargetPick = true
        }
        AlertDialog(
            onDismissRequest = { csvFormatPick = false },
            title = { Text("选择 CSV 格式") },
            text = {
                Column {
                    Row(
                        Modifier.fillMaxWidth().clickable { proceed(false) }.padding(vertical = 12.dp)
                    ) {
                        Column {
                            Text("完整格式", style = MaterialTheme.typography.bodyLarge)
                            Text(
                                "包含备注、标签等全部字段（name, url, username, password, note, tags）。",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    Row(
                        Modifier.fillMaxWidth().clickable { proceed(true) }.padding(vertical = 12.dp)
                    ) {
                        Column {
                            Text("浏览器精简格式", style = MaterialTheme.typography.bodyLarge)
                            Text(
                                "仅 name, url, username, password 四列，便于导入 Chrome / Edge 等浏览器。",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { csvFormatPick = false }) { Text("取消") } }
        )
    }

    // ---- CSV import target picker ----
    if (csvImportTargetPick) {
        VaultPickDialog(
            title = "导入到哪个密码库？",
            vaults = vaults.map { it.id to it.name },
            onPick = { id ->
                csvImportTargetPick = false
                val csv = pendingImportCsv
                pendingImportCsv = null
                if (csv != null) previewCsvImport(csv, id)
            },
            onDismiss = { csvImportTargetPick = false; pendingImportCsv = null }
        )
    }

    // ---- CSV export vault picker ----
    if (csvExportTargetPick) {
        VaultPickDialog(
            title = "导出哪个密码库？",
            vaults = vaults.map { it.id to it.name },
            onPick = { id ->
                csvExportTargetPick = false
                launchCsvSave(id)
            },
            onDismiss = { csvExportTargetPick = false }
        )
    }

    // ---- Import JSON: ask password ----
    if (importPasswordPrompt) {
        BackupPasswordDialog(
            title = "恢复备份",
            message = "请输入创建此备份时使用的密码。",
            onDismiss = { importPasswordPrompt = false; pendingImportJson = null },
            onConfirm = { pw ->
                importPasswordPrompt = false
                val json = pendingImportJson
                pendingImportJson = null
                if (json != null) previewJsonImport(json, pw)
            }
        )
    }

    if (pendingImportPreview != null && pendingImportAction != null) {
        ImportPreviewDialog(
            preview = pendingImportPreview!!,
            onDismiss = {
                pendingImportPreview = null
                pendingImportAction = null
            },
            onConfirm = { strategy -> executePendingImport(strategy) }
        )
    }

    if (showPasteImport) {
        PasteImportDialog(
            onDismiss = { showPasteImport = false },
            onImport = { content ->
                showPasteImport = false
                handleImportText(content)
            }
        )
    }

    if (showAbout) {
        AlertDialog(
            onDismissRequest = { showAbout = false },
            title = { Text("离线密码库") },
            text = {
                Text(
                    "完全离线的密码管理器，不申请联网权限，不使用云端或服务器。\n\n" +
                        "密码库使用 AES-256-GCM 加密，数字密码或普通密码通过 " +
                        "PBKDF2-HMAC-SHA256 派生密钥。12 个助记词仅用于最终恢复，不可用于日常解锁。\n\n" +
                        "版本 ${BuildConfig.VERSION_NAME}。"
                )
            },
            confirmButton = { TextButton(onClick = { showAbout = false }) { Text("关闭") } }
        )
    }
}

private sealed interface SettingsPendingImportAction {
    data class Json(val content: String, val password: String) : SettingsPendingImportAction
    data class Csv(val content: String, val vaultId: String) : SettingsPendingImportAction
}

private fun autoLockLabel(seconds: Int): String = when {
    seconds == 0 -> "立即锁定"
    seconds < 60 -> "$seconds 秒后"
    seconds % 60 == 0 -> "${seconds / 60} 分钟后"
    else -> "$seconds 秒后"
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text.uppercase(Locale.ROOT),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.primary,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(start = 4.dp, bottom = 8.dp)
    )
}

@Composable
private fun ToggleSetting(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun ClickSetting(title: String, subtitle: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            if (subtitle.isNotEmpty()) {
                Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun SettingDivider() {
    androidx.compose.material3.HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
}

@Composable
private fun ChoiceDialog(
    title: String,
    options: List<Pair<Int, String>>,
    selected: Int,
    onSelect: (Int) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                options.forEach { (value, label) ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onSelect(value) }.padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(selected = selected == value, onClick = { onSelect(value) })
                        Text(label)
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("关闭") } }
    )
}

@Composable
private fun VaultPickDialog(
    title: String,
    vaults: List<Pair<String, String>>,
    onPick: (String) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                vaults.forEach { (id, name) ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onPick(id) }.padding(vertical = 12.dp)
                    ) { Text(name, style = MaterialTheme.typography.bodyLarge) }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("取消") } }
    )
}

@Composable
private fun ChangeMasterDialog(
    credentialType: com.offlinevault.security.CredentialType,
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit
) {
    var old by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val strength = PasswordStrengthChecker.evaluate(new)
    val keyboardType = if (credentialType.isNumeric)
        androidx.compose.ui.text.input.KeyboardType.NumberPassword
    else androidx.compose.ui.text.input.KeyboardType.Password

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("修改${credentialType.noun}") },
        text = {
            Column {
                PasswordVisualField(value = old, onValueChange = { old = credentialType.sanitize(it) }, label = "当前${credentialType.noun}", revealed = false, keyboardType = keyboardType)
                Spacer(Modifier.height(10.dp))
                PasswordVisualField(value = new, onValueChange = { new = credentialType.sanitize(it) }, label = "新${credentialType.displayName}", revealed = false, keyboardType = keyboardType)
                if (credentialType == com.offlinevault.security.CredentialType.PASSWORD) {
                    Spacer(Modifier.height(8.dp))
                    com.offlinevault.ui.components.StrengthMeter(score = strength.score, level = strength.level)
                }
                Spacer(Modifier.height(10.dp))
                PasswordVisualField(value = confirm, onValueChange = { confirm = credentialType.sanitize(it) }, label = "确认${credentialType.noun}", revealed = false, keyboardType = keyboardType)
                if (error != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(error!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                error = when {
                    !credentialType.isValid(new) ->
                        if (credentialType.isNumeric) "请输入${credentialType.minLength}位数字密码"
                        else "密码至少需要${credentialType.minLength}个字符"
                    new != confirm -> "两次输入的${credentialType.noun}不一致"
                    else -> null
                }
                if (error == null) onConfirm(old, new)
            }) { Text("修改") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
    )
}

@Composable
private fun ChangeRecoveryDialog(
    currentQuestion: String,
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit
) {
    var question by remember { mutableStateOf(currentQuestion) }
    var answer by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("安全问题") },
        text = {
            Column {
                VaultTextField(value = question, onValueChange = { question = it }, label = "安全问题")
                Spacer(Modifier.height(10.dp))
                PasswordVisualField(
                    value = answer,
                    onValueChange = { answer = it },
                    label = "新答案",
                    revealed = false,
                    keyboardType = androidx.compose.ui.text.input.KeyboardType.Password
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    "答案至少 ${com.offlinevault.security.KeyManager.MIN_NEW_RECOVERY_ANSWER_LENGTH} 个字符。" +
                        "避免使用姓名、生日或容易猜到的公开信息。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (question.isNotBlank() &&
                        answer.trim().length >= com.offlinevault.security.KeyManager.MIN_NEW_RECOVERY_ANSWER_LENGTH
                    ) {
                        onConfirm(question, answer)
                    }
                },
                enabled = question.isNotBlank() &&
                    answer.trim().length >= com.offlinevault.security.KeyManager.MIN_NEW_RECOVERY_ANSWER_LENGTH
            ) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
    )
}

@Composable
private fun BackupPasswordDialog(
    title: String,
    message: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit
) {
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                Text(
                    "$message 至少需要 ${com.offlinevault.data.backup.BackupManager.MIN_BACKUP_PASSWORD_LENGTH} 个字符。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(12.dp))
                PasswordVisualField(value = password, onValueChange = { password = it }, label = "备份密码", revealed = false)
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (password.length >= com.offlinevault.data.backup.BackupManager.MIN_BACKUP_PASSWORD_LENGTH) {
                        onConfirm(password)
                    }
                },
                enabled = password.length >= com.offlinevault.data.backup.BackupManager.MIN_BACKUP_PASSWORD_LENGTH
            ) {
                Text("继续")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
    )
}
