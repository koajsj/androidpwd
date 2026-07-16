package com.offlinevault.ui.screens

import android.view.autofill.AutofillManager
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.RadioButton
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.offlinevault.data.backup.ImportPreview
import com.offlinevault.data.backup.ImportResult
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.security.LockGuard
import com.offlinevault.security.PasswordStrengthChecker
import com.offlinevault.security.SessionManager
import com.offlinevault.ui.components.CardShape
import com.offlinevault.ui.components.ImportPreviewDialog
import com.offlinevault.ui.components.PasteImportDialog
import com.offlinevault.ui.components.PasswordVisualField
import com.offlinevault.ui.components.RiskChip
import com.offlinevault.utils.FileIo
import com.offlinevault.utils.FilePickerCompat
import com.offlinevault.utils.ImportFormatDetector
import com.offlinevault.utils.toUserMessage
import com.offlinevault.viewmodel.PasswordListViewModel
import com.offlinevault.viewmodel.SortOrder
import kotlinx.coroutines.launch
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordListScreen(
    viewModel: PasswordListViewModel,
    onOpenItem: (String) -> Unit,
    onAddItem: () -> Unit,
    onOpenSettings: () -> Unit
) {
    val items by viewModel.tiaomu.collectAsStateWithLifecycle()
    val query by viewModel.sousuoChaxun.collectAsStateWithLifecycle()
    val tags by viewModel.biaoqianLiebiao.collectAsStateWithLifecycle()
    val activeTag by viewModel.dangqianBiaoqian.collectAsStateWithLifecycle()
    val vaultName by viewModel.mimakuMingcheng.collectAsStateWithLifecycle()
    val vaults by viewModel.vaults.collectAsStateWithLifecycle()
    val errorMessage by viewModel.cuowuXinxi.collectAsStateWithLifecycle()
    val selectedIds by viewModel.selectedIds.collectAsStateWithLifecycle()
    val sortOrder by viewModel.sortOrder.collectAsStateWithLifecycle()
    val selectionMode = selectedIds.isNotEmpty()

    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    var importJsonPasswordPrompt by remember { mutableStateOf(false) }
    var pendingImportJson by remember { mutableStateOf<String?>(null) }
    var pendingImportAction by remember { mutableStateOf<ListPendingImportAction?>(null) }
    var pendingImportPreview by remember { mutableStateOf<ImportPreview?>(null) }
    var showPasteImport by remember { mutableStateOf(false) }
    var showSort by remember { mutableStateOf(false) }
    var confirmBatchDelete by remember { mutableStateOf(false) }
    var showVaultPicker by remember { mutableStateOf(false) }
    var showCreateVault by remember { mutableStateOf(false) }
    var showRenameVault by remember { mutableStateOf(false) }
    var confirmVaultDelete by remember { mutableStateOf(false) }
    var vaultNameDraft by remember { mutableStateOf("") }

    // While selecting, the system back button exits selection instead of leaving the screen.
    BackHandler(enabled = selectionMode) { viewModel.clearSelection() }

    // Autofill enablement nudge: shown until the user enables Offline Vault as the system service.
    val autofillManager = remember { context.getSystemService(AutofillManager::class.java) }
    val autofillSupported = remember {
        runCatching { autofillManager?.isAutofillSupported == true }.getOrDefault(false)
    }
    var autofillEnabled by remember {
        mutableStateOf(runCatching { autofillManager?.hasEnabledAutofillServices() == true }.getOrDefault(false))
    }
    // Session dismiss (✕) hides until next launch; "不再提示" persists across launches.
    var autofillBannerDismissed by remember { mutableStateOf(false) }
    val autofillBannerHidden by viewModel.autofillBannerHidden.collectAsStateWithLifecycle()
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        autofillEnabled = runCatching { autofillManager?.hasEnabledAutofillServices() == true }.getOrDefault(false)
    }

    fun toast(msg: String) = scope.launch { snackbar.showSnackbar(msg) }
    fun importToast(r: ImportResult) = toast(r.toUserMessage())

    androidx.compose.runtime.LaunchedEffect(errorMessage) {
        errorMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.qingchuCuowu()
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
            viewModel.yulanCsvDaoru(text) { result ->
                val preview = result.preview
                if (preview != null) {
                    pendingImportAction = ListPendingImportAction.Csv(text)
                    pendingImportPreview = preview
                } else {
                    toast(result.errorMessage ?: "无法预览 CSV")
                }
            }
        } else {
            pendingImportJson = text
            importJsonPasswordPrompt = true
        }
    }

    fun executePendingImport(strategy: com.offlinevault.data.backup.ImportConflictStrategy) {
        when (val action = pendingImportAction) {
            is ListPendingImportAction.Csv -> {
                viewModel.daoruCsv(action.content, strategy) { importToast(it) }
            }
            is ListPendingImportAction.Json -> {
                viewModel.daoruJson(action.content, action.password, strategy) { importToast(it) }
            }
            null -> Unit
        }
        pendingImportAction = null
        pendingImportPreview = null
    }

    fun handlePickedUri(uri: Uri?) {
        LockGuard.suppressNextBackground = false
        if (uri == null) return
        // The activity may have auto-locked while the system picker was in front. Do not retain a
        // selected backup or attempt an import after the in-memory data-encryption key is cleared.
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
        LockGuard.suppressNextBackground = true
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
        LockGuard.suppressNextBackground = false
        showPasteImport = true
        toast("文件选择器不可用，已打开粘贴导入")
    }

    Scaffold(
        containerColor = androidx.compose.ui.graphics.Color.Transparent,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            val barColors = TopAppBarDefaults.topAppBarColors(
                containerColor = androidx.compose.ui.graphics.Color.Transparent,
                titleContentColor = MaterialTheme.colorScheme.onBackground
            )
            if (selectionMode) {
                TopAppBar(
                    title = { Text("已选 ${selectedIds.size} 项", fontWeight = FontWeight.Bold) },
                    navigationIcon = {
                        IconButton(onClick = { viewModel.clearSelection() }) {
                            Icon(Icons.Filled.Close, contentDescription = "退出多选")
                        }
                    },
                    actions = {
                        IconButton(onClick = { confirmBatchDelete = true }) {
                            Icon(Icons.Filled.Delete, contentDescription = "删除所选", tint = MaterialTheme.colorScheme.error)
                        }
                    },
                    colors = barColors
                )
            } else {
                TopAppBar(
                    title = {
                        TextButton(
                            onClick = { showVaultPicker = true },
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text(vaultName.ifEmpty { "我的密码" }, fontWeight = FontWeight.Bold)
                            Icon(Icons.Filled.ArrowDropDown, contentDescription = "切换密码库")
                        }
                    },
                    actions = {
                        Box {
                            IconButton(onClick = { showSort = true }) {
                                Icon(Icons.AutoMirrored.Filled.Sort, contentDescription = "排序")
                            }
                            DropdownMenu(expanded = showSort, onDismissRequest = { showSort = false }) {
                                SortMenuItem("最近更新", SortOrder.UPDATED, sortOrder) {
                                    viewModel.setSortOrder(it); showSort = false
                                }
                                SortMenuItem("标题", SortOrder.TITLE, sortOrder) {
                                    viewModel.setSortOrder(it); showSort = false
                                }
                                SortMenuItem("密码强度（弱在前）", SortOrder.STRENGTH, sortOrder) {
                                    viewModel.setSortOrder(it); showSort = false
                                }
                            }
                        }
                        IconButton(onClick = { launchImport() }) {
                            Icon(Icons.Filled.Download, contentDescription = "导入密码")
                        }
                        IconButton(onClick = onOpenSettings) {
                            Icon(Icons.Filled.Settings, contentDescription = "设置")
                        }
                    },
                    colors = barColors
                )
            }
        },
        floatingActionButton = {
            if (!selectionMode) {
                FloatingActionButton(
                    onClick = onAddItem,
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = Color.White
                ) {
                    Icon(Icons.Filled.Add, contentDescription = "添加密码")
                }
            }
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            if (autofillSupported && !autofillEnabled && !autofillBannerDismissed && !autofillBannerHidden) {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f))
                        .padding(start = 14.dp, end = 4.dp, top = 8.dp, bottom = 4.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("开启自动填充", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                            Text(
                                "在其他应用和网页中自动填充、保存账号，需先在系统设置中启用。",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(onClick = { autofillBannerDismissed = true }) {
                            Icon(Icons.Filled.Close, contentDescription = "忽略", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                        TextButton(onClick = { viewModel.buZaiTishiZidongTianchong() }) {
                            Text("不再提示", color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        TextButton(onClick = onOpenSettings) { Text("去设置") }
                    }
                }
                Spacer(Modifier.height(8.dp))
            }

            OutlinedTextField(
                value = query,
                onValueChange = viewModel::shezhiChaxun,
                placeholder = { Text("搜索标题、用户名或网址…") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline
                )
            )

            if (tags.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(tags) { tag ->
                        FilterChip(
                            selected = activeTag == tag,
                            onClick = { viewModel.qiehuanBiaoqian(tag) },
                            label = { Text(tag) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.2f),
                                selectedLabelColor = MaterialTheme.colorScheme.primary
                            )
                        )
                    }
                }
            }

            Spacer(Modifier.height(12.dp))

            if (items.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        if (query.isBlank() && activeTag == null) "暂无密码，点击 + 添加，或用右上角导入。"
                        else "没有匹配结果",
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(bottom = 90.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(items, key = { it.id }) { item ->
                        PasswordCard(
                            item = item,
                            selected = item.id in selectedIds,
                            selectionMode = selectionMode,
                            onClick = {
                                if (selectionMode) viewModel.toggleSelected(item.id) else onOpenItem(item.id)
                            },
                            onLongClick = { viewModel.toggleSelected(item.id) },
                            onToggleFavorite = { viewModel.toggleFavorite(item.id, !item.favorite) }
                        )
                    }
                }
            }
        }
    }

    if (showVaultPicker) {
        AlertDialog(
            onDismissRequest = { showVaultPicker = false },
            title = { Text("密码库") },
            text = {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(max = 360.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    Text(
                        "选择要查看的密码库。每个密码库的数据独立保存。",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(8.dp))
                    vaults.forEach { vault ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .clickable {
                                    viewModel.qiehuanMimaku(vault.id)
                                    showVaultPicker = false
                                }
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = vault.id == viewModel.dangqianMimakuId(),
                                onClick = {
                                    viewModel.qiehuanMimaku(vault.id)
                                    showVaultPicker = false
                                }
                            )
                            Text(
                                vault.name,
                                modifier = Modifier.weight(1f),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = {
                        showVaultPicker = false
                        vaultNameDraft = ""
                        showCreateVault = true
                    }) {
                        Icon(Icons.Filled.Add, contentDescription = null)
                        Spacer(Modifier.size(6.dp))
                        Text("新建密码库")
                    }
                    TextButton(
                        onClick = {
                            showVaultPicker = false
                            vaultNameDraft = vaultName
                            showRenameVault = true
                        },
                        enabled = vaultName.isNotBlank()
                    ) {
                        Icon(Icons.Filled.Edit, contentDescription = null)
                        Spacer(Modifier.size(6.dp))
                        Text("重命名当前密码库")
                    }
                    TextButton(
                        onClick = {
                            showVaultPicker = false
                            confirmVaultDelete = true
                        },
                        enabled = vaults.size > 1,
                        colors = androidx.compose.material3.ButtonDefaults.textButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Icon(Icons.Filled.Delete, contentDescription = null)
                        Spacer(Modifier.size(6.dp))
                        Text(if (vaults.size > 1) "删除当前密码库" else "至少保留一个密码库")
                    }
                }
            },
            confirmButton = { TextButton(onClick = { showVaultPicker = false }) { Text("完成") } }
        )
    }

    if (showCreateVault || showRenameVault) {
        val creating = showCreateVault
        AlertDialog(
            onDismissRequest = {
                showCreateVault = false
                showRenameVault = false
            },
            title = { Text(if (creating) "新建密码库" else "重命名密码库") },
            text = {
                Column {
                    Text(
                        if (creating) "创建后会自动切换到新密码库。" else "仅修改显示名称，不影响其中的密码数据。",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = vaultNameDraft,
                        onValueChange = { vaultNameDraft = it.take(40) },
                        label = { Text("密码库名称") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val action: ((Boolean, String?) -> Unit) -> Unit = if (creating) {
                        { callback -> viewModel.xinjianMimaku(vaultNameDraft, callback) }
                    } else {
                        { callback -> viewModel.chongmingmingMimaku(vaultNameDraft, callback) }
                    }
                    action { success, message ->
                        if (success) {
                            showCreateVault = false
                            showRenameVault = false
                            toast(if (creating) "已创建密码库" else "已重命名密码库")
                        } else {
                            toast(message ?: "操作失败")
                        }
                    }
                }, enabled = vaultNameDraft.isNotBlank()) { Text("保存") }
            },
            dismissButton = {
                TextButton(onClick = {
                    showCreateVault = false
                    showRenameVault = false
                }) { Text("取消") }
            }
        )
    }

    if (confirmVaultDelete) {
        AlertDialog(
            onDismissRequest = { confirmVaultDelete = false },
            title = { Text("删除“${vaultName.ifBlank { "当前密码库" }}”吗？") },
            text = {
                Text(
                    "其中的所有密码、回收站项目和密码历史都会永久删除，无法恢复。将自动切换到另一个密码库。"
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.shanchuDangqianMimaku { success, message ->
                        confirmVaultDelete = false
                        toast(if (success) "已删除密码库" else (message ?: "删除失败"))
                    }
                }) { Text("永久删除", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmVaultDelete = false }) { Text("取消") } }
        )
    }

    if (importJsonPasswordPrompt) {
        var password by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { importJsonPasswordPrompt = false; pendingImportJson = null },
            title = { Text("恢复备份") },
            text = {
                Column {
                    Text(
                        "请输入创建此备份时使用的密码。",
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
                        importJsonPasswordPrompt = false
                        val json = pendingImportJson
                        pendingImportJson = null
                        if (json != null) {
                            viewModel.yulanJsonDaoru(json, password) { result ->
                                val preview = result.preview
                                if (preview != null) {
                                    pendingImportAction = ListPendingImportAction.Json(json, password)
                                    pendingImportPreview = preview
                                } else {
                                    toast(result.errorMessage ?: "无法预览备份")
                                }
                            }
                        }
                    },
                    enabled = password.isNotEmpty()
                ) { Text("继续") }
            },
            dismissButton = {
                TextButton(onClick = { importJsonPasswordPrompt = false; pendingImportJson = null }) { Text("取消") }
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

    if (confirmBatchDelete) {
        AlertDialog(
            onDismissRequest = { confirmBatchDelete = false },
            title = { Text("删除所选密码？") },
            text = { Text("选中的 ${selectedIds.size} 项将被移到回收站，30 天后自动永久删除。期间可在「设置 → 回收站」中恢复。") },
            confirmButton = {
                TextButton(onClick = {
                    confirmBatchDelete = false
                    viewModel.deleteSelected { ok, count ->
                        toast(if (ok) "已移到回收站 $count 项" else "删除失败")
                    }
                }) { Text("移到回收站", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmBatchDelete = false }) { Text("取消") } }
        )
    }
}

private sealed interface ListPendingImportAction {
    data class Json(val content: String, val password: String) : ListPendingImportAction
    data class Csv(val content: String) : ListPendingImportAction
}

@Composable
private fun SortMenuItem(
    label: String,
    order: SortOrder,
    current: SortOrder,
    onPick: (SortOrder) -> Unit
) {
    DropdownMenuItem(
        text = { Text(label) },
        onClick = { onPick(order) },
        leadingIcon = {
            if (order == current) {
                Icon(Icons.Filled.Check, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            }
        }
    )
}

@OptIn(ExperimentalFoundationApi::class, ExperimentalLayoutApi::class)
@Composable
private fun PasswordCard(
    item: PasswordEntity,
    selected: Boolean,
    selectionMode: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    onToggleFavorite: () -> Unit
) {
    val level = PasswordStrengthChecker.levelFor(item.strengthScore)
    val tagList = item.tags.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(if (pressed) 0.98f else 1f, label = "cardPress")

    val borderColor = if (selected) MaterialTheme.colorScheme.primary
    else MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)
    val containerColor = if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)
    else MaterialTheme.colorScheme.surface

    Row(
        Modifier
            .fillMaxWidth()
            .scale(scale)
            .shadow(10.dp, CardShape, clip = false, spotColor = Color.Black, ambientColor = Color.Black)
            .clip(CardShape)
            .background(containerColor)
            .border(1.dp, borderColor, CardShape)
            .combinedClickable(
                interactionSource = interaction,
                indication = null,
                onClick = onClick,
                onLongClick = onLongClick
            )
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(44.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(MaterialTheme.colorScheme.primary.copy(alpha = if (selected) 1f else 0.16f)),
            contentAlignment = Alignment.Center
        ) {
            if (selected) {
                Icon(Icons.Filled.Check, contentDescription = "已选中", tint = Color.White)
            } else {
                Text(
                    item.title.take(1).uppercase(Locale.ROOT).ifEmpty { "?" },
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.titleMedium
                )
            }
        }
        Spacer(Modifier.size(14.dp))
        Column(Modifier.weight(1f)) {
            Text(item.title.ifEmpty { "无标题" }, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, maxLines = 1)
            if (item.username.isNotEmpty()) {
                Text(item.username, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
            }
            Text(
                "••••••••••",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontFamily = FontFamily.Monospace
            )
            if (tagList.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    tagList.take(3).forEach { tag ->
                        Box(
                            Modifier
                                .widthIn(max = 140.dp)
                                .clip(RoundedCornerShape(6.dp))
                                .background(MaterialTheme.colorScheme.surfaceVariant)
                                .padding(horizontal = 8.dp, vertical = 2.dp)
                        ) {
                            Text(
                                tag,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }
        }
        Spacer(Modifier.size(8.dp))
        if (!selectionMode) {
            IconButton(onClick = onToggleFavorite) {
                Icon(
                    if (item.favorite) Icons.Filled.Star else Icons.Filled.StarBorder,
                    contentDescription = if (item.favorite) "取消收藏" else "收藏",
                    tint = if (item.favorite) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        RiskChip(level = level)
    }
}
