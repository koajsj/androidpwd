package com.offlinevault.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TextButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Switch
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.offlinevault.utils.Formatters
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.offlinevault.ui.components.SectionCard
import com.offlinevault.viewmodel.PasswordHealthViewModel
import com.offlinevault.security.SecurityLevel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordHealthScreen(
    viewModel: PasswordHealthViewModel,
    onBack: () -> Unit,
    onOpenItem: (String) -> Unit,
    onEditItem: (String) -> Unit
) {
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { viewModel.load() }
    val state by viewModel.state.collectAsStateWithLifecycle()
    val recovery by viewModel.recoveryStatus.collectAsStateWithLifecycle()
    var filter by rememberSaveable { mutableStateOf("全部") }
    var showAgeReminder by rememberSaveable { mutableStateOf(false) }
    val initialRiskIds by viewModel.initialRiskIds.collectAsStateWithLifecycle()
    val currentRiskIds = state.report.security.weakCredentialIds + state.report.security.reusedCredentialIds

    Scaffold(
        containerColor = Color.Transparent,
        topBar = {
            TopAppBar(
                title = { Text("密码安全体检", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = { TextButton(onClick = { viewModel.load() }, enabled = !state.loading) { Text("重新分析") } },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    titleContentColor = MaterialTheme.colorScheme.onBackground
                )
            )
        }
    ) { padding ->
        when {
            state.loading -> Box(
                Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) { CircularProgressIndicator(color = MaterialTheme.colorScheme.primary) }

            state.error != null -> Box(
                Modifier.fillMaxSize().padding(padding).padding(24.dp),
                contentAlignment = Alignment.Center
            ) { Text(state.error!!, color = MaterialTheme.colorScheme.error) }

            else -> {
                val report = state.report
                val neutralRiskColor = MaterialTheme.colorScheme.onSurfaceVariant
                val highRiskColor = MaterialTheme.colorScheme.error
                val mediumRiskColor = MaterialTheme.colorScheme.tertiary
                // A health report can legitimately contain every entry in a large imported
                // vault. Lazy rendering keeps this screen responsive instead of composing every
                // weak/reused/stale row before the first frame appears.
                LazyColumn(
                    Modifier
                        .fillMaxSize()
                        .padding(padding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    item { SummaryCard(report) }
                    item {
                        Column {
                            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                listOf("全部", "弱密码", "重复密码").forEach { name ->
                                    FilterChip(selected = filter == name, onClick = { filter = name }, label = { Text(name) })
                                }
                            }
                            initialRiskIds?.takeIf { it.isNotEmpty() }?.let { initial ->
                                Text("本次会话已处理 ${initial.count { it !in currentRiskIds }} / ${initial.size} 项初始风险记录",
                                    style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                    item {
                        SectionCard {
                            Column {
                                Text("恢复与备份", style = MaterialTheme.typography.titleMedium)
                                if (recovery.credentialType.isNumeric) Text("当前使用短 PIN：取得密钥包裹文件的攻击者可离线猜测。建议在设置中改用高熵主密码。",
                                    color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                                Text("助记词：${if (recovery.mnemonic) "已配置" else "未配置或不可读取"}")
                                Text("密保：${if (recovery.question) "已配置；请避免易猜答案" else "未配置或不可读取"}")
                                Text(when (val at = recovery.lastBackupAt) {
                                    null -> "备份状态暂不可读取"
                                    0L -> "尚无本机导出记录（历史备份状态未知）"
                                    else -> "最后写入加密备份：${Formatters.fullDate(at)}"
                                })
                                Text("文件写入不等于已实测恢复，请离线妥善保管备份密码并核对恢复结果。",
                                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }

                    if (report.security.recommendations.isNotEmpty()) {
                        item {
                            SectionCard {
                                Column {
                                    Text("本地安全建议", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                                    Spacer(Modifier.height(8.dp))
                                    report.security.recommendations.forEach { recommendation ->
                                        Text(
                                            "• $recommendation",
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }

                    if (currentRiskIds.isEmpty()) {
                        item {
                            SectionCard {
                                Text(
                                    if (report.total == 0) "还没有密码可供体检。"
                                    else "未发现明显问题，你的密码状况良好。",
                                    style = MaterialTheme.typography.bodyLarge
                                )
                            }
                        }
                    }
                    if ((filter == "弱密码" && report.weak.isEmpty()) || (filter == "重复密码" && report.reused.isEmpty())) {
                        item { Text("此筛选下没有风险记录。", style = MaterialTheme.typography.bodyMedium) }
                    }

                    if (filter != "重复密码") issueSection(
                        title = "弱密码",
                        description = "强度过低，容易被破解，建议尽快更换。",
                        color = highRiskColor,
                        entries = report.weak,
                        onOpenItem = onOpenItem,
                        onEditItem = onEditItem
                    )
                    if (filter != "弱密码") issueSection(
                        title = "重复使用的密码",
                        description = "多个账号使用了相同的密码，一处泄露会牵连其它账号。",
                        color = mediumRiskColor,
                        entries = report.reused,
                        onOpenItem = onOpenItem,
                        onEditItem = onEditItem
                    )
                    item {
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Text("显示久未更新提醒（不扣分）", modifier = Modifier.weight(1f))
                            Switch(checked = showAgeReminder, onCheckedChange = { showAgeReminder = it })
                        }
                    }
                    if (showAgeReminder) issueSection(
                        title = "长期未更新",
                        description = "仅提示记录年龄，不表示密码已泄露或必须定期更换。发现弱密码、重复使用或明确泄露时再更换。",
                        color = neutralRiskColor,
                        entries = report.stale,
                        onOpenItem = onOpenItem,
                        onEditItem = onEditItem
                    )
                    item { Spacer(Modifier.height(14.dp)) }
                }
            }
        }
    }
}

@Composable
private fun SummaryCard(report: PasswordHealthViewModel.HealthReport) {
    val scoreColor = when (report.security.level) {
        SecurityLevel.LOW -> MaterialTheme.colorScheme.primary
        SecurityLevel.MEDIUM -> MaterialTheme.colorScheme.tertiary
        SecurityLevel.HIGH, SecurityLevel.CRITICAL -> MaterialTheme.colorScheme.error
    }
    val levelText = when (report.security.level) {
        SecurityLevel.LOW -> "良好"
        SecurityLevel.MEDIUM -> "需要注意"
        SecurityLevel.HIGH -> "风险较高"
        SecurityLevel.CRITICAL -> "风险严重"
    }
    SectionCard {
        Column {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.weight(1f).padding(end = 12.dp)) {
                    Text("密码安全评分", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text("完全在本地分析，不会上传密码", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text("${report.security.score}", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = scoreColor)
                    Text(levelText, style = MaterialTheme.typography.bodySmall, color = scoreColor)
                }
            }
            Spacer(Modifier.height(8.dp))
            Text("共分析 ${report.total} 条密码 · 根据长度、复杂度和唯一性评分；年龄不扣分", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(16.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Stat("弱密码", report.weak.size, MaterialTheme.colorScheme.error)
                Stat("重复", report.reused.size, MaterialTheme.colorScheme.tertiary)
                // Stale is the least severe and purely informational — neutral, not "safe green".
                Stat("久未更新", report.stale.size, MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun Stat(label: String, count: Int, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text("$count", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = color)
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun LazyListScope.issueSection(
    title: String,
    description: String,
    color: Color,
    entries: List<PasswordHealthViewModel.HealthEntry>,
    onOpenItem: (String) -> Unit,
    onEditItem: (String) -> Unit
) {
    if (entries.isEmpty()) return
    item(key = "health-section-$title") {
        Column(Modifier.padding(top = 10.dp)) {
            Text(
                "$title · ${entries.size}",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = color
            )
            Text(description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
    items(entries, key = { entry -> "health-$title-${entry.id}" }) { entry ->
        SectionCard {
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable { onOpenItem(entry.id) }
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(entry.title, style = MaterialTheme.typography.bodyLarge)
                    if (entry.username.isNotBlank()) {
                        Text(
                            entry.username,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                TextButton(onClick = { onEditItem(entry.id) }) { Text("修改") }
                Icon(
                    Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
