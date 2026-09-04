package com.offlinevault.ui.screens

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import com.offlinevault.security.CredentialType
import com.offlinevault.security.RiskLevel
import com.offlinevault.security.RiskScore
import com.offlinevault.ui.components.IconBadge
import com.offlinevault.ui.components.PasswordVisualField
import com.offlinevault.ui.components.PrimaryButton
import com.offlinevault.ui.components.SectionCard
import com.offlinevault.viewmodel.UnlockUiState
import kotlin.math.roundToInt

@Composable
fun UnlockScreen(
    state: UnlockUiState,
    biometricEnabled: Boolean,
    riskScore: RiskScore,
    credentialType: CredentialType,
    onUnlock: (String) -> Unit,
    onBiometric: () -> Unit,
    onForgot: () -> Unit
) {
    var password by remember { mutableStateOf("") }
    var reveal by remember { mutableStateOf(false) }

    // Shake the card horizontally whenever shakeTrigger changes (wrong password), then clear input.
    val shake = remember { Animatable(0f) }
    LaunchedEffect(state.shakeTrigger) {
        if (state.shakeTrigger > 0) {
            val pattern = listOf(0f, -16f, 14f, -10f, 6f, 0f)
            for (target in pattern) {
                shake.animateTo(target, tween(40))
            }
            password = ""
        }
    }

    // Auto-submit a numeric PIN as soon as it reaches the required length.
    LaunchedEffect(password) {
        if (credentialType.isNumeric && !state.isLoading && state.delaySeconds <= 0 && credentialType.isValid(password)) {
            onUnlock(password)
        }
    }

    // Auto-trigger biometric once when arriving on a locked screen with biometrics enabled.
    LaunchedEffect(biometricEnabled, riskScore.allowsBiometricOnly) {
        if (biometricEnabled && riskScore.allowsBiometricOnly) onBiometric()
    }

    Column(
        Modifier
            .fillMaxSize()
            .systemBarsPadding()
            .imePadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        IconBadge(icon = Icons.Filled.Lock)
        Spacer(Modifier.height(16.dp))
        Text("离线密码库", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        Text(
            if (riskScore.level == RiskLevel.HIGH) {
                "检测到本地安全风险，请输入${credentialType.noun}"
            } else {
                "已锁定，请输入${credentialType.noun}"
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(28.dp))

        SectionCard(
            modifier = Modifier.offset { IntOffset(shake.value.roundToInt(), 0) }
        ) {
            Column {
                PasswordVisualField(
                    value = password,
                    onValueChange = { password = credentialType.sanitize(it) },
                    label = credentialType.displayName,
                    revealed = reveal,
                    keyboardType = if (credentialType.isNumeric) KeyboardType.NumberPassword else KeyboardType.Password,
                    trailing = {
                        TextButton(onClick = { reveal = !reveal }) {
                            Text(if (reveal) "隐藏" else "显示")
                        }
                    }
                )
                if (state.errorMessage != null) {
                    Spacer(Modifier.height(10.dp))
                    Text(state.errorMessage, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                }
                Spacer(Modifier.height(16.dp))
                PrimaryButton(
                    text = if (state.isLoading) "正在解锁…" else "解锁",
                    // Avoid a costly PBKDF2 attempt (and a failed-attempt penalty) for a
                    // partially entered PIN or too-short master password.
                    enabled = credentialType.isValid(password) && !state.isLoading,
                    onClick = { onUnlock(password) },
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        if (riskScore.reasons.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            Text(
                riskScore.reasons.joinToString("；"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        if (biometricEnabled && riskScore.allowsBiometricOnly) {
            Spacer(Modifier.height(16.dp))
            OutlinedButton(onClick = onBiometric, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                Icon(Icons.Filled.Fingerprint, contentDescription = null)
                Spacer(Modifier.height(0.dp))
                Text("  使用指纹解锁")
            }
        } else if (biometricEnabled) {
            Spacer(Modifier.height(12.dp))
            Text(
                "高风险状态下已暂停单独使用指纹解锁。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onForgot) {
            Text("忘记${credentialType.noun}？", color = MaterialTheme.colorScheme.primary)
        }
    }
}
