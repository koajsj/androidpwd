package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.offlinevault.data.backup.BackupManager
import com.offlinevault.data.backup.ImportConflictStrategy
import com.offlinevault.data.backup.ImportPreview
import com.offlinevault.data.backup.ImportResult
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.data.preferences.SecurityPreferences
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.VaultDeleteResult
import com.offlinevault.data.repository.VaultRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job

/** List ordering options. Favorites always pin above these. */
enum class SortOrder { UPDATED, TITLE, STRENGTH }

@OptIn(ExperimentalCoroutinesApi::class, FlowPreview::class)
class PasswordListViewModel(
    private val mimaCangku: PasswordRepository,
    private val mimakuCangku: VaultRepository,
    private val beifenGuanli: BackupManager,
    private val anquanPianhao: SecurityPreferences
) : ViewModel() {

    data class ImportPreviewPayload(
        val preview: ImportPreview? = null,
        val errorMessage: String? = null
    )

    /** Persisted: user permanently hid the autofill enablement banner. */
    val autofillBannerHidden: StateFlow<Boolean> =
        anquanPianhao.autofillBannerDismissedFlow
            .stateIn(viewModelScope, SharingStarted.Eagerly, false)

    fun buZaiTishiZidongTianchong() {
        viewModelScope.launch {
            try {
                anquanPianhao.setAutofillBannerDismissed(true)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Non-critical UI preference; ignore persistence failures.
            }
        }
    }

    private val mimakuId = MutableStateFlow("")
    private val chaxun = MutableStateFlow("")
    private val biaoqianGuolv = MutableStateFlow<String?>(null)

    val sousuoChaxun: StateFlow<String> = chaxun.asStateFlow()
    val dangqianBiaoqian: StateFlow<String?> = biaoqianGuolv.asStateFlow()

    private val _mimakuMingcheng = MutableStateFlow("")
    val mimakuMingcheng: StateFlow<String> = _mimakuMingcheng.asStateFlow()

    /** All vaults for the switcher. Their names are decrypted only while the session is unlocked. */
    val vaults = mimakuCangku.allVaults()
        .catch { yichang ->
            if (yichang is CancellationException) throw yichang
            emit(emptyList())
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _cuowuXinxi = MutableStateFlow<String?>(null)
    val cuowuXinxi: StateFlow<String?> = _cuowuXinxi.asStateFlow()

    // Debounce only the typed query (blank emits immediately so the initial load isn't delayed).
    private val chaxunFangdou = chaxun.debounce { if (it.isBlank()) 0L else 200L }

    private val paixu = MutableStateFlow(SortOrder.UPDATED)
    val sortOrder: StateFlow<SortOrder> = paixu.asStateFlow()
    fun setSortOrder(order: SortOrder) { paixu.value = order }

    // Vault mutations are destructive or change the active destination. Keep them serial so a
    // rapid double-tap cannot create duplicate vaults or race a deletion against a rename.
    private var vaultMutationJob: Job? = null

    private data class ListQuery(val kuId: String, val query: String, val tag: String?, val sort: SortOrder)

    val tiaomu: StateFlow<List<PasswordEntity>> =
        combine(mimakuId, chaxunFangdou, biaoqianGuolv, paixu) { kuId, cxWen, biaoqian, sort ->
            ListQuery(kuId, cxWen, biaoqian, sort)
        }
            .flatMapLatest { q ->
                val source = when {
                    q.kuId.isEmpty() -> kotlinx.coroutines.flow.flowOf(emptyList())
                    q.tag != null -> mimaCangku.byTag(q.kuId, q.tag)
                    q.query.isNotBlank() -> mimaCangku.search(q.kuId, q.query.trim())
                    else -> mimaCangku.passwordsByVault(q.kuId)
                }
                source.map { sortItems(it, q.sort) }
            }
            // Row decryption + sorting happen off the main thread so large vaults never jank the UI.
            .flowOn(Dispatchers.Default)
            .catch { yichang ->
                if (yichang is CancellationException) throw yichang
                _cuowuXinxi.value = "无法读取密码数据"
                emit(emptyList())
            }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    // Favorites always float to the top, then the chosen order applies.
    private fun sortItems(list: List<PasswordEntity>, order: SortOrder): List<PasswordEntity> {
        val base = when (order) {
            SortOrder.UPDATED -> compareByDescending<PasswordEntity> { it.updatedAt }
            SortOrder.TITLE -> compareBy<PasswordEntity> { it.title.lowercase() }
            SortOrder.STRENGTH -> compareBy<PasswordEntity> { it.strengthScore }
        }
        return list.sortedWith(compareByDescending<PasswordEntity> { it.favorite }.then(base))
    }

    // ---- Selection (batch operations) ----
    private val xuanzhong = MutableStateFlow<Set<String>>(emptySet())
    val selectedIds: StateFlow<Set<String>> = xuanzhong.asStateFlow()

    fun toggleSelected(id: String) {
        val cur = xuanzhong.value
        xuanzhong.value = if (id in cur) cur - id else cur + id
    }

    fun clearSelection() { xuanzhong.value = emptySet() }

    fun deleteSelected(onResult: (Boolean, Int) -> Unit) {
        val ids = xuanzhong.value.toList()
        if (ids.isEmpty()) return
        viewModelScope.launch {
            try {
                mimaCangku.deleteMany(ids)
                xuanzhong.value = emptySet()
                onResult(true, ids.size)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, 0)
            }
        }
    }

    fun toggleFavorite(id: String, favorite: Boolean) {
        viewModelScope.launch {
            try {
                mimaCangku.setFavorite(id, favorite)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Non-critical; ignore.
            }
        }
    }

    /** All distinct tags present in the current vault, for the filter row. */
    val biaoqianLiebiao: StateFlow<List<String>> =
        mimakuId.flatMapLatest { kuId ->
            if (kuId.isEmpty()) kotlinx.coroutines.flow.flowOf(emptyList())
            else mimaCangku.passwordsByVault(kuId)
        }.map { liebiao ->
            liebiao.flatMap { it.tags.split(",") }
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .distinct()
                .sorted()
        }.flowOn(Dispatchers.Default)
            .catch { yichang ->
                if (yichang is CancellationException) throw yichang
                emit(emptyList())
            }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    /** Opens the single default vault, creating it on first run. Used as the app's home. */
    fun jiazaiMoren() {
        viewModelScope.launch {
            try {
                val mimaku = mimakuCangku.ensureDefault()
                mimakuId.value = mimaku.id
                _mimakuMingcheng.value = mimaku.name
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                _cuowuXinxi.value = "无法打开密码库，请重新锁定后再试"
            }
        }
    }

    fun qiehuanMimaku(vaultId: String) {
        if (vaultId == mimakuId.value) return
        viewModelScope.launch {
            try {
                val vault = mimakuCangku.getById(vaultId) ?: run {
                    _cuowuXinxi.value = "未找到密码库"
                    return@launch
                }
                mimakuId.value = vault.id
                _mimakuMingcheng.value = vault.name
                biaoqianGuolv.value = null
                xuanzhong.value = emptySet()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                _cuowuXinxi.value = "无法切换密码库"
            }
        }
    }

    fun xinjianMimaku(name: String, onResult: (Boolean, String?) -> Unit) {
        if (vaultMutationJob?.isActive == true) return
        val normalized = name.trim()
        if (normalized.isEmpty()) {
            onResult(false, "请输入密码库名称")
            return
        }
        if (normalized.length > VaultRepository.MAX_NAME_LENGTH) {
            onResult(false, "名称不能超过 ${VaultRepository.MAX_NAME_LENGTH} 个字符")
            return
        }
        vaultMutationJob = viewModelScope.launch {
            try {
                if (mimakuCangku.allOnce().any { it.name.equals(normalized, ignoreCase = true) }) {
                    onResult(false, "已存在同名密码库")
                    return@launch
                }
                val vault = mimakuCangku.create(normalized, "lock")
                mimakuId.value = vault.id
                _mimakuMingcheng.value = vault.name
                biaoqianGuolv.value = null
                xuanzhong.value = emptySet()
                onResult(true, null)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "无法创建密码库")
            }
        }
    }

    fun chongmingmingMimaku(name: String, onResult: (Boolean, String?) -> Unit) {
        if (vaultMutationJob?.isActive == true) return
        val vaultId = mimakuId.value
        val normalized = name.trim()
        if (vaultId.isEmpty()) {
            onResult(false, "当前密码库尚未加载")
            return
        }
        if (normalized.isEmpty()) {
            onResult(false, "请输入密码库名称")
            return
        }
        if (normalized.length > VaultRepository.MAX_NAME_LENGTH) {
            onResult(false, "名称不能超过 ${VaultRepository.MAX_NAME_LENGTH} 个字符")
            return
        }
        vaultMutationJob = viewModelScope.launch {
            try {
                if (mimakuCangku.allOnce().any { it.id != vaultId && it.name.equals(normalized, ignoreCase = true) }) {
                    onResult(false, "已存在同名密码库")
                    return@launch
                }
                val vault = mimakuCangku.rename(vaultId, normalized)
                if (vault == null) {
                    onResult(false, "未找到当前密码库")
                } else {
                    _mimakuMingcheng.value = vault.name
                    onResult(true, null)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "无法重命名密码库")
            }
        }
    }

    fun shanchuDangqianMimaku(onResult: (Boolean, String?) -> Unit) {
        if (vaultMutationJob?.isActive == true) return
        val vaultId = mimakuId.value
        if (vaultId.isEmpty()) {
            onResult(false, "当前密码库尚未加载")
            return
        }
        vaultMutationJob = viewModelScope.launch {
            try {
                when (val result = mimakuCangku.deleteKeepingOne(vaultId)) {
                    is VaultDeleteResult.Deleted -> {
                        mimakuId.value = result.fallbackVault.id
                        _mimakuMingcheng.value = result.fallbackVault.name
                        biaoqianGuolv.value = null
                        xuanzhong.value = emptySet()
                        onResult(true, null)
                    }
                    VaultDeleteResult.LastVault -> onResult(false, "至少保留一个密码库")
                    VaultDeleteResult.NotFound -> onResult(false, "未找到当前密码库")
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                onResult(false, "无法删除密码库")
            }
        }
    }

    /** Current vault id, or empty if not loaded yet. */
    fun dangqianMimakuId(): String = mimakuId.value

    fun yulanJsonDaoru(neirong: String, mima: String, huidiao: (ImportPreviewPayload) -> Unit) {
        viewModelScope.launch {
            val jieguo = try {
                ImportPreviewPayload(
                    preview = withContext(Dispatchers.Default) { beifenGuanli.previewJsonBackup(neirong, mima) }
                )
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                ImportPreviewPayload(errorMessage = "无法预览备份：密码错误、格式无效或文件已损坏")
            }
            huidiao(jieguo)
        }
    }

    fun yulanCsvDaoru(neirong: String, huidiao: (ImportPreviewPayload) -> Unit) {
        viewModelScope.launch {
            val jieguo = try {
                val mubiao = mimakuId.value.ifEmpty { mimakuCangku.ensureDefault().id }
                ImportPreviewPayload(
                    preview = withContext(Dispatchers.Default) { beifenGuanli.previewChromeCsv(neirong, mubiao) }
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ImportPreviewPayload(errorMessage = e.message ?: "无法预览 CSV")
            }
            huidiao(jieguo)
        }
    }

    fun daoruJson(
        neirong: String,
        mima: String,
        celue: ImportConflictStrategy = ImportConflictStrategy.SKIP,
        huidiao: (ImportResult) -> Unit
    ) {
        viewModelScope.launch {
            val jieguo = try {
                withContext(Dispatchers.Default) { beifenGuanli.importJsonBackup(neirong, mima, celue) }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                ImportResult(0, 0, 0, listOf("导入失败，请检查文件后重试"))
            }
            huidiao(jieguo)
        }
    }

    fun daoruCsv(
        neirong: String,
        celue: ImportConflictStrategy = ImportConflictStrategy.SKIP,
        huidiao: (ImportResult) -> Unit
    ) {
        viewModelScope.launch {
            val jieguo = try {
                val mubiao = mimakuId.value.ifEmpty { mimakuCangku.ensureDefault().id }
                withContext(Dispatchers.Default) { beifenGuanli.importChromeCsv(neirong, mubiao, celue) }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                ImportResult(0, 0, 0, listOf("导入失败，请检查文件后重试"))
            }
            huidiao(jieguo)
        }
    }

    fun qingchuCuowu() {
        _cuowuXinxi.value = null
    }

    fun shezhiChaxun(zhi: String) { chaxun.value = zhi }

    fun qiehuanBiaoqian(biaoqian: String) {
        biaoqianGuolv.value = if (biaoqianGuolv.value == biaoqian) null else biaoqian
    }
}
