package com.offlinevault.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AutoMode
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.AlertDialog
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.Lifecycle
import com.offlinevault.security.PasswordStrengthChecker
import com.offlinevault.ui.components.PasswordGeneratorSheet
import com.offlinevault.ui.components.PasswordVisualField
import com.offlinevault.ui.components.PrimaryButton
import com.offlinevault.ui.components.SectionCard
import com.offlinevault.ui.components.SectionHeading
import com.offlinevault.ui.components.StrengthMeter
import com.offlinevault.ui.components.VaultTextField
import com.offlinevault.viewmodel.PasswordEditViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordEditScreen(
    viewModel: PasswordEditViewModel,
    vaultId: String,
    passwordId: String?,
    onDone: () -> Unit,
    onBack: () -> Unit
) {
    LaunchedEffect(vaultId, passwordId) { viewModel.initialize(vaultId, passwordId) }
    val form by viewModel.form.collectAsStateWithLifecycle()
    val errorMessage by viewModel.errorMessage.collectAsStateWithLifecycle()
    val isSaving by viewModel.isSaving.collectAsStateWithLifecycle()
    val editable = !isSaving
    val hasUnsavedChanges by viewModel.hasUnsavedChanges.collectAsStateWithLifecycle()

    var reveal by remember { mutableStateOf(false) }
    var showGenerator by remember { mutableStateOf(false) }
    var showDiscardConfirmation by remember { mutableStateOf(false) }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    val strength = remember(form.password) { PasswordStrengthChecker.evaluate(form.password) }
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) { reveal = false; showGenerator = false }

    fun requestBack() {
        when {
            isSaving -> Unit
            hasUnsavedChanges -> showDiscardConfirmation = true
            else -> onBack()
        }
    }

    BackHandler(enabled = isSaving || hasUnsavedChanges) { requestBack() }

    LaunchedEffect(errorMessage) {
        errorMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.clearError()
        }
    }

    Scaffold(
        containerColor = androidx.compose.ui.graphics.Color.Transparent,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(if (form.isEditing) "编辑密码" else "新建密码") },
                navigationIcon = {
                    IconButton(onClick = ::requestBack, enabled = !isSaving) {
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
                .wrapContentWidth()
                .widthIn(max = 720.dp)
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            SectionHeading("登录信息", "标题用于识别账号，密码将加密保存在本机。")
            SectionCard {
                Column {
                    VaultTextField(value = form.title, onValueChange = { v -> viewModel.update { it.copy(title = v) } }, label = "标题", enabled = editable)
                    Spacer(Modifier.height(12.dp))
                    VaultTextField(value = form.username, onValueChange = { v -> viewModel.update { it.copy(username = v) } }, label = "用户名 / 邮箱", enabled = editable)
                    Spacer(Modifier.height(12.dp))
                    PasswordVisualField(
                        value = form.password,
                        onValueChange = { v -> viewModel.setPassword(v) },
                        label = "密码",
                        revealed = reveal,
                        enabled = editable,
                        trailing = {
                            Row {
                                IconButton(onClick = { reveal = !reveal }, enabled = editable) {
                                    Icon(
                                        if (reveal) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                        contentDescription = if (reveal) "隐藏密码" else "显示密码",
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                IconButton(onClick = { showGenerator = true }, enabled = editable) {
                                    Icon(Icons.Filled.AutoMode, contentDescription = "生成密码", tint = MaterialTheme.colorScheme.primary)
                                }
                            }
                        }
                    )
                    if (form.password.isNotEmpty()) {
                        Spacer(Modifier.height(10.dp))
                        StrengthMeter(score = strength.score, level = strength.level)
                    }
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = { showGenerator = true }, enabled = editable) {
                        Icon(Icons.Filled.AutoMode, contentDescription = null)
                        Text("  生成强密码")
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
            SectionHeading("其他信息", "网址、标签和备注均为选填。")

            SectionCard {
                Column {
                    VaultTextField(value = form.url, onValueChange = { v -> viewModel.update { it.copy(url = v) } }, label = "网址", keyboardType = KeyboardType.Uri, enabled = editable)
                    Spacer(Modifier.height(12.dp))
                    VaultTextField(
                        value = form.tags,
                        onValueChange = { v -> viewModel.update { it.copy(tags = v) } },
                        label = "标签（每行一个）",
                        singleLine = false,
                        enabled = editable
                    )
                    Spacer(Modifier.height(12.dp))
                    VaultTextField(value = form.note, onValueChange = { v -> viewModel.update { it.copy(note = v) } }, label = "备注（已加密）", singleLine = false, enabled = editable)
                }
            }

            Spacer(Modifier.height(24.dp))
            PrimaryButton(
                text = if (isSaving) "正在保存…" else "保存",
                loading = isSaving,
                onClick = {
                    viewModel.save { ok, message ->
                        if (ok) {
                            onDone()
                        } else if (!message.isNullOrBlank()) {
                            scope.launch { snackbar.showSnackbar(message) }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = editable
            )
            Spacer(Modifier.height(24.dp))
        }
    }

    if (showGenerator) {
        PasswordGeneratorSheet(
            onDismiss = { showGenerator = false },
            onUse = { generated ->
                viewModel.setPassword(generated)
                showGenerator = false
            }
        )
    }

    if (showDiscardConfirmation) {
        AlertDialog(
            onDismissRequest = { showDiscardConfirmation = false },
            title = { Text("放弃未保存的更改？") },
            text = { Text("当前填写的内容尚未保存，返回后将无法恢复。") },
            confirmButton = {
                TextButton(onClick = onBack) { Text("放弃更改") }
            },
            dismissButton = {
                TextButton(onClick = { showDiscardConfirmation = false }) { Text("继续编辑") }
            }
        )
    }
}
