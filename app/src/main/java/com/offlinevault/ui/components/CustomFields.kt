package com.offlinevault.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.offlinevault.data.model.CustomField
import com.offlinevault.data.model.CustomFieldCodec
import com.offlinevault.data.model.CustomFieldType
import com.offlinevault.security.SessionManager
import com.offlinevault.security.Totp
import com.offlinevault.security.VaultLockedException
import com.offlinevault.utils.ClipboardHelper
import kotlinx.coroutines.delay
import kotlinx.coroutines.CancellationException

@Composable
fun CustomFieldEditor(fields: List<CustomField>, enabled: Boolean, onChange: (List<CustomField>) -> Unit) {
    SectionHeading("安全字段", "恢复代码、许可证等敏感文本；TOTP 可输入 Base32 密钥或 otpauth://totp/ 配置。")
    fields.forEach { field ->
        key(field.id) {
            var reveal by remember { mutableStateOf(false) }
            LifecycleEventEffect(Lifecycle.Event.ON_STOP) { reveal = false }
            SectionCard {
                Column {
                    VaultTextField(field.label, { name ->
                        onChange(fields.map { if (it.id == field.id) it.copy(label = name) else it })
                    }, label = if (field.type == CustomFieldType.TOTP) "验证码名称" else "字段名称", enabled = enabled)
                    Spacer(Modifier.height(8.dp))
                    PasswordVisualField(field.value, { value ->
                        onChange(fields.map { if (it.id == field.id) it.copy(value = value) else it })
                    }, label = if (field.type == CustomFieldType.TOTP) "Base32 密钥或 TOTP 配置" else "敏感内容",
                        revealed = reveal, enabled = enabled,
                        trailing = { TextButton(onClick = { reveal = !reveal }, enabled = enabled) { Text(if (reveal) "隐藏" else "显示") } })
                    if (field.label.length > CustomFieldCodec.MAX_LABEL_LENGTH || field.value.length > CustomFieldCodec.MAX_VALUE_LENGTH) {
                        Text("名称最多 64 字符，内容最多 8192 字符；请缩短后再保存。", color = MaterialTheme.colorScheme.error)
                    }
                    TextButton(onClick = { onChange(fields.filterNot { it.id == field.id }) }, enabled = enabled) {
                        Text("删除字段", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
            Spacer(Modifier.height(10.dp))
        }
    }
    Row {
        TextButton(onClick = { onChange(fields + CustomField()) }, enabled = enabled && fields.size < CustomFieldCodec.MAX_FIELDS) { Text("添加安全文本") }
        TextButton(onClick = { onChange(fields + CustomField(label = "验证码", type = CustomFieldType.TOTP)) },
            enabled = enabled && fields.size < CustomFieldCodec.MAX_FIELDS) { Text("添加 TOTP") }
    }
    if (fields.any { it.type == CustomFieldType.TOTP }) {
        Text("验证码使用系统时间，请保持设备时间准确。与密码放在同一保险库不构成独立的第二因素。",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
fun CustomFieldDetails(fields: List<CustomField>, onMessage: (String) -> Unit) {
    fields.forEach { field -> key(field.id) {
        var reveal by remember { mutableStateOf(false) }
        var code by remember { mutableStateOf("") }
        var remaining by remember { mutableIntStateOf(0) }
        val generation = remember { SessionManager.sessionGeneration }
        val context = LocalContext.current
        LifecycleEventEffect(Lifecycle.Event.ON_STOP) { reveal = false; code = "" }
        val config = remember(field.value, field.type) {
            if (field.type == CustomFieldType.TOTP) runCatching { Totp.parse(field.value) }.getOrNull() else null
        }
        LaunchedEffect(reveal, config) {
            code = ""
            if (reveal && config != null) {
                try {
                    while (true) {
                        SessionManager.requireActiveSession(generation)
                        val now = System.currentTimeMillis()
                        code = Totp.code(config, now)
                        remaining = Totp.remainingSeconds(config, now)
                        delay(1000)
                    }
                } catch (_: VaultLockedException) { reveal = false }
                catch (e: CancellationException) { throw e }
                catch (_: Exception) {
                    reveal = false
                    onMessage("无法生成验证码，请检查系统时间和配置")
                }
                finally { code = "" }
            }
        }
        SectionCard {
            Column {
                Text(field.label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(if (!reveal) "••••••••" else if (field.type == CustomFieldType.TOTP) code.ifEmpty { "—" } else field.value,
                    fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                if (reveal && config != null) Text("${remaining} 秒后更新 · 使用系统时间", style = MaterialTheme.typography.bodySmall)
                Row {
                    TextButton(onClick = { reveal = !reveal; if (!reveal) code = "" }) { Text(if (reveal) "隐藏" else "显示") }
                    TextButton(onClick = {
                        val copied = runCatching {
                            SessionManager.withActiveSessionNow(generation) {
                                val value = if (field.type == CustomFieldType.TOTP) Totp.code(requireNotNull(config)) else field.value
                                ClipboardHelper.copySensitive(context, "安全字段", value, 10)
                            }
                        }.getOrDefault(false)
                        onMessage(if (copied) "已复制，10 秒后清除" else "复制失败，请重新解锁或检查配置")
                    }, enabled = field.value.isNotEmpty()) { Text(if (config != null) "复制验证码" else "复制内容") }
                }
            }
        }
        Spacer(Modifier.height(12.dp))
    } }
}
