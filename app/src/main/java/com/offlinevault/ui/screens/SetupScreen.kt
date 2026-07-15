package com.offlinevault.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.offlinevault.security.CredentialType
import com.offlinevault.security.MnemonicManager
import com.offlinevault.security.PasswordStrengthChecker
import com.offlinevault.ui.components.IconBadge
import com.offlinevault.ui.components.PasswordVisualField
import com.offlinevault.ui.components.PrimaryButton
import com.offlinevault.ui.components.SectionCard
import com.offlinevault.ui.components.StrengthMeter
import com.offlinevault.ui.components.VaultTextField

@Composable
fun SetupScreen(
    setupError: String?,
    biometricAvailable: Boolean,
    onCreate: (master: String, question: String, answer: String, mnemonicPhrase: String, enableBiometric: Boolean, type: CredentialType) -> Unit
) {
    val mnemonicManager = remember { MnemonicManager() }
    var credType by remember { mutableStateOf(CredentialType.PIN6) }
    var master by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var question by remember { mutableStateOf("") }
    var answer by remember { mutableStateOf("") }
    var enableBiometric by remember { mutableStateOf(false) }
    var revealMaster by remember { mutableStateOf(false) }
    var localError by remember { mutableStateOf<String?>(null) }
    var pendingMnemonicWords by remember { mutableStateOf<List<String>?>(null) }

    val strength = PasswordStrengthChecker.evaluate(master)
    val canSubmit = credType.isValid(master) && confirm.isNotEmpty() &&
        question.isNotBlank() && answer.isNotBlank()

    fun setType(type: CredentialType) {
        credType = type
        master = ""
        confirm = ""
        localError = null
    }

    val keyboardType = if (credType.isNumeric) KeyboardType.NumberPassword else KeyboardType.Password

    if (pendingMnemonicWords != null) {
        val words = pendingMnemonicWords!!
        Column(
            Modifier
                .fillMaxSize()
                .systemBarsPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp)
        ) {
            Spacer(Modifier.height(12.dp))
            IconBadge(icon = Icons.Filled.Shield)
            Spacer(Modifier.height(16.dp))
            Text("保存恢复助记词", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            Text(
                "助记词不会明文保存，也不能用于日常进入 App。它只在忘记主密码且忘记密保答案时，用于恢复密钥并重设主密码。",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(24.dp))
            MnemonicConfirmationContent(
                words = words,
                actionLabel = "完成初始化",
                onBack = { pendingMnemonicWords = null },
                onConfirm = {
                    onCreate(
                        master,
                        question,
                        answer,
                        words.joinToString(" "),
                        enableBiometric,
                        credType
                    )
                }
            )
            Spacer(Modifier.height(24.dp))
        }
        return
    }

    Column(
        Modifier
            .fillMaxSize()
            .systemBarsPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp)
    ) {
        Spacer(Modifier.height(24.dp))
        IconBadge(icon = Icons.Filled.Shield)
        Spacer(Modifier.height(16.dp))
        Text("设置密码库", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(6.dp))
        Text(
            "解锁凭据用于保护本机加密密码库。应用不会保存该凭据，没有正确的安全问题答案将无法恢复。",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(24.dp))

        SectionCard {
            Column {
                Text("解锁方式", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CredentialType.entries.forEach { type ->
                        SegmentOption(
                            label = when (type) {
                                CredentialType.PIN4 -> "4位数字密码"
                                CredentialType.PIN6 -> "6位数字密码"
                                CredentialType.PASSWORD -> "混合密码"
                            },
                            selected = credType == type,
                            modifier = Modifier.weight(1f),
                            onClick = { setType(type) }
                        )
                    }
                }
                Spacer(Modifier.height(16.dp))
                PasswordVisualField(
                    value = master,
                    onValueChange = { master = credType.sanitize(it) },
                    label = credType.displayName,
                    revealed = revealMaster,
                    keyboardType = keyboardType,
                    trailing = { RevealToggle(revealMaster) { revealMaster = !revealMaster } }
                )
                if (credType == CredentialType.PASSWORD && master.isNotEmpty()) {
                    Spacer(Modifier.height(10.dp))
                    StrengthMeter(score = strength.score, level = strength.level)
                }
                Spacer(Modifier.height(12.dp))
                PasswordVisualField(
                    value = confirm,
                    onValueChange = { confirm = credType.sanitize(it) },
                    label = "确认${credType.noun}",
                    revealed = revealMaster,
                    keyboardType = keyboardType
                )
                if (credType.isNumeric) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "短数字密码使用方便，但安全性低于普通密码。建议启用指纹解锁并保持禁止截屏。",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        SectionCard {
            Column {
                Text("恢复访问", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp))
                Text(
                    "密保答案用于常规恢复；12 个助记词会在下一步生成，仅展示一次，用于最终恢复。答案不区分大小写。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(12.dp))
                VaultTextField(value = question, onValueChange = { question = it }, label = "安全问题")
                Spacer(Modifier.height(12.dp))
                PasswordVisualField(
                    value = answer,
                    onValueChange = { answer = it },
                    label = "问题答案",
                    revealed = false,
                    keyboardType = KeyboardType.Password
                )
            }
        }

        if (biometricAvailable) {
            Spacer(Modifier.height(16.dp))
            SectionCard {
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Fingerprint, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Text("  启用指纹解锁（可选）", style = MaterialTheme.typography.bodyLarge)
                    }
                    Switch(checked = enableBiometric, onCheckedChange = { enableBiometric = it })
                }
            }
        }

        val shownError = localError ?: setupError
        if (shownError != null) {
            Spacer(Modifier.height(12.dp))
            Text(shownError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }

        Spacer(Modifier.height(24.dp))
        PrimaryButton(
            text = "下一步",
            enabled = canSubmit,
            onClick = {
                localError = when {
                    !credType.isValid(master) ->
                        if (credType.isNumeric) "请输入${credType.minLength}位数字密码"
                        else "密码至少需要${credType.minLength}个字符"
                    master != confirm -> "两次输入的${credType.noun}不一致"
                    else -> null
                }
                if (localError == null) pendingMnemonicWords = mnemonicManager.generateWords()
            },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun SegmentOption(label: String, selected: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Box(
        modifier = modifier
            .height(44.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(
                if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.22f)
                else MaterialTheme.colorScheme.surfaceVariant
            )
            .border(
                1.dp,
                if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                RoundedCornerShape(12.dp)
            )
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelLarge,
            textAlign = TextAlign.Center,
            color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
        )
    }
}

@Composable
private fun RevealToggle(revealed: Boolean, onToggle: () -> Unit) {
    val icon: ImageVector = if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility
    IconButton(onClick = onToggle) {
        Icon(icon, contentDescription = "切换显示状态", tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
