package com.offlinevault.ui.screens

import androidx.compose.ui.res.vectorResource
import com.offlinevault.R
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.offlinevault.security.CredentialType
import com.offlinevault.security.MnemonicManager
import com.offlinevault.security.PasswordStrengthChecker
import com.offlinevault.ui.components.IconBadge
import com.offlinevault.ui.components.PasswordVisualField
import com.offlinevault.ui.components.PrimaryButton
import com.offlinevault.ui.components.SectionCard
import com.offlinevault.ui.components.SecureWindowEffect
import com.offlinevault.ui.components.StrengthMeter

@Composable
fun SetupScreen(
    setupError: String?,
    setupInProgress: Boolean,
    biometricAvailable: Boolean,
    onCreate: (master: String, mnemonicPhrase: String, enableBiometric: Boolean, type: CredentialType) -> Unit
) {
    val mnemonicManager = remember { MnemonicManager() }
    var credType by remember { mutableStateOf(CredentialType.PASSWORD) }
    var master by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var enableBiometric by remember { mutableStateOf(false) }
    var revealMaster by remember { mutableStateOf(false) }
    var localError by remember { mutableStateOf<String?>(null) }
    var pendingMnemonicWords by remember { mutableStateOf<List<String>?>(null) }
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) { revealMaster = false }

    // The initial recovery phrase is displayed only here; it must never be capturable even when
    // the user later chooses to disable the general screenshot-block setting.
    SecureWindowEffect(enabled = pendingMnemonicWords != null)

    val strength = remember(master) { PasswordStrengthChecker.evaluate(master) }
    val canSubmit = credType.isValid(master) && confirm.isNotEmpty()

    fun setType(type: CredentialType) {
        credType = type
        revealMaster = false
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
                .wrapContentWidth()
                .widthIn(max = 560.dp)
                .systemBarsPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp)
        ) {
            Spacer(Modifier.height(12.dp))
            IconBadge(icon = ImageVector.vectorResource(R.drawable.ic_shield))
            Spacer(Modifier.height(16.dp))
            Text("保存恢复助记词", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            Text(
                "助记词不会明文保存，也不能用于日常进入 App。忘记解锁凭据时，它只能用于恢复密钥并重设凭据。",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(24.dp))
            MnemonicConfirmationContent(
                words = words,
                scrollable = false,
                actionLabel = if (setupInProgress) "正在创建…" else "完成初始化",
                enabled = !setupInProgress,
                errorMessage = setupError,
                onBack = { if (!setupInProgress) pendingMnemonicWords = null },
                onConfirm = {
                    onCreate(
                        master,
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
            .wrapContentWidth()
            .widthIn(max = 560.dp)
            .systemBarsPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp)
    ) {
        Spacer(Modifier.height(24.dp))
        IconBadge(icon = ImageVector.vectorResource(R.drawable.ic_shield))
        Spacer(Modifier.height(16.dp))
        Text("设置密码库", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(6.dp))
        Text(
            "建议使用高熵主密码或长口令。应用不保存凭据；解锁凭据和助记词全部丢失后，数据将无法恢复。",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(24.dp))

        SectionCard {
            Column {
                Text("解锁方式", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CredentialType.setupOptions.forEach { type ->
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
                        "短 PIN 只有有限组合。取得本地密钥包裹文件的攻击者可以离线猜测，应用内重试延迟和指纹不能消除此风险。推荐改用高熵主密码。",
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
                    "不使用容易被离线猜测的密保答案。下一步将生成 12 个随机助记词，请离线抄写并完成抽词确认。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
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
                        Icon(ImageVector.vectorResource(R.drawable.ic_fingerprint), contentDescription = null, tint = MaterialTheme.colorScheme.primary)
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
    val icon: ImageVector = if (revealed) ImageVector.vectorResource(R.drawable.ic_visibility_off) else ImageVector.vectorResource(R.drawable.ic_visibility)
    IconButton(onClick = onToggle) {
        Icon(icon, contentDescription = if (revealed) "隐藏主密码" else "显示主密码", tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
