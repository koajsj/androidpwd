package com.offlinevault.ui.screens

import androidx.compose.animation.Crossfade
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.offlinevault.security.PasswordStrengthChecker
import com.offlinevault.ui.components.SectionCard
import com.offlinevault.ui.components.StrengthMeter
import com.offlinevault.utils.ClipboardHelper
import com.offlinevault.utils.Formatters
import com.offlinevault.viewmodel.PasswordDetailViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordDetailScreen(
    viewModel: PasswordDetailViewModel,
    passwordId: String,
    clipboardSeconds: Int,
    onBack: () -> Unit,
    onEdit: () -> Unit
) {
    LaunchedEffect(passwordId) { viewModel.load(passwordId) }
    val item by viewModel.item.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()
    val historyCount by viewModel.historyCount.collectAsStateWithLifecycle()
    val history by viewModel.history.collectAsStateWithLifecycle()

    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var reveal by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var showHistory by remember { mutableStateOf(false) }

    DisposableEffect(Unit) {
        onDispose { viewModel.clearHistory() }
    }

    fun toast(message: String) = scope.launch { snackbar.showSnackbar(message) }

    Scaffold(
        containerColor = androidx.compose.ui.graphics.Color.Transparent,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("详情", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    IconButton(onClick = onEdit, enabled = item != null) {
                        Icon(Icons.Filled.Edit, contentDescription = "编辑")
                    }
                    IconButton(onClick = { confirmDelete = true }, enabled = item != null) {
                        Icon(Icons.Filled.Delete, contentDescription = "删除", tint = MaterialTheme.colorScheme.error)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = androidx.compose.ui.graphics.Color.Transparent,
                    titleContentColor = MaterialTheme.colorScheme.onBackground
                )
            )
        }
    ) { padding ->
        val current = item
        if (current == null) {
            if (error != null) {
                Box(
                    Modifier.fillMaxSize().padding(padding).padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(error!!, color = MaterialTheme.colorScheme.error)
                }
            }
            return@Scaffold
        }
        val strength = PasswordStrengthChecker.evaluate(current.password)

        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            Text(current.title, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(16.dp))

            SectionCard {
                Column {
                    FieldRow(
                        label = "用户名",
                        value = current.username.ifEmpty { "—" },
                        onCopy = if (current.username.isNotEmpty()) {
                            {
                                ClipboardHelper.copySensitive(context, "用户名", current.username, clipboardSeconds)
                                toast(
                                    if (clipboardSeconds > 0) "用户名已复制，将在 ${clipboardSeconds} 秒后清除"
                                    else "用户名已复制"
                                )
                            }
                        } else null
                    )
                    Divider()
                    // Password with reveal + copy.
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("密码", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.height(2.dp))
                            Crossfade(targetState = reveal, label = "reveal") { shown ->
                                Text(
                                    if (shown) current.password else "••••••••••••",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                        IconButton(onClick = { reveal = !reveal }) {
                            Icon(
                                if (reveal) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = "切换显示状态",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(onClick = {
                            ClipboardHelper.copySensitive(context, "密码", current.password, clipboardSeconds)
                            toast(
                                if (clipboardSeconds > 0) "密码已复制，将在 ${clipboardSeconds} 秒后清除"
                                else "密码已复制"
                            )
                        }) {
                            Icon(Icons.Filled.ContentCopy, contentDescription = "复制", tint = MaterialTheme.colorScheme.primary)
                        }
                    }
                    Spacer(Modifier.height(4.dp))
                    StrengthMeter(score = strength.score, level = strength.level)
                    if (strength.warnings.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            strength.warnings.first(),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            if (current.url.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                SectionCard {
                    FieldRow(
                        label = "网站",
                        value = current.url,
                        onCopy = {
                            ClipboardHelper.copyPlain(context, "网址", current.url)
                            toast("网址已复制")
                        }
                    )
                }
            }

            if (current.tags.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                SectionCard {
                    Column {
                        Text("标签", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Spacer(Modifier.height(4.dp))
                        Text(current.tags.joinToString(", "), style = MaterialTheme.typography.bodyLarge)
                    }
                }
            }

            if (current.note.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                SectionCard {
                    Column {
                        Text("备注", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Spacer(Modifier.height(4.dp))
                        Text(current.note, style = MaterialTheme.typography.bodyLarge)
                    }
                }
            }

            if (historyCount > 0) {
                Spacer(Modifier.height(12.dp))
                SectionCard {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable { viewModel.loadHistory(); showHistory = true }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("历史密码", style = MaterialTheme.typography.bodyLarge)
                            Text(
                                "保留最近 $historyCount 条曾用密码",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Icon(
                            Icons.AutoMirrored.Filled.KeyboardArrowRight,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            Spacer(Modifier.height(16.dp))
            Text(
                "更新于 ${Formatters.fullDate(current.updatedAt)}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(24.dp))
        }
    }

    if (showHistory) {
        AlertDialog(
            onDismissRequest = { showHistory = false; viewModel.clearHistory() },
            title = { Text("历史密码") },
            text = {
                if (history.isEmpty()) {
                    Text("没有可显示的历史密码。", style = MaterialTheme.typography.bodyMedium)
                } else {
                    Column(
                        Modifier
                            .heightIn(max = 360.dp)
                            .verticalScroll(rememberScrollState())
                    ) {
                        Text(
                            "曾经使用过的密码，最新在前。点击复制。",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(12.dp))
                        history.forEach { entry ->
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        ClipboardHelper.copySensitive(context, "历史密码", entry.password, clipboardSeconds)
                                        toast(
                                            if (clipboardSeconds > 0) "已复制，将在 ${clipboardSeconds} 秒后清除"
                                            else "已复制"
                                        )
                                    }
                                    .padding(vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(
                                        entry.password,
                                        style = MaterialTheme.typography.titleMedium,
                                        fontFamily = FontFamily.Monospace
                                    )
                                    Text(
                                        "更换于 ${Formatters.relativeTime(entry.changedAt)}",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Icon(
                                    Icons.Filled.ContentCopy,
                                    contentDescription = "复制",
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showHistory = false; viewModel.clearHistory() }) { Text("关闭") }
            }
        )
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("删除密码？") },
            text = { Text("此项目将被移到回收站，30 天后自动永久删除。期间可在「设置 → 回收站」中恢复。") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    viewModel.delete { ok, message ->
                        if (ok) onBack()
                        else if (!message.isNullOrBlank()) toast(message)
                    }
                }) { Text("删除", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("取消") } }
        )
    }
}

@Composable
private fun FieldRow(label: String, value: String, onCopy: (() -> Unit)?) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(2.dp))
            Text(value, style = MaterialTheme.typography.titleMedium)
        }
        if (onCopy != null) {
            IconButton(onClick = onCopy) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "复制", tint = MaterialTheme.colorScheme.primary)
            }
        }
    }
}

@Composable
private fun Divider() {
    androidx.compose.material3.HorizontalDivider(
        color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)
    )
}
