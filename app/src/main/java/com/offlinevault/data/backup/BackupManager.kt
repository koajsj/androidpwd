package com.offlinevault.data.backup

import com.google.gson.Gson
import com.google.gson.JsonParser
import com.offlinevault.autofill.OriginMatcher
import com.offlinevault.data.model.VaultEntity
import com.offlinevault.data.repository.DecryptedPassword
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.security.CryptoManager
import com.offlinevault.security.KdfVersions
import com.google.gson.stream.JsonWriter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.util.Locale
import javax.crypto.SecretKey
import kotlin.coroutines.coroutineContext

/**
 * Handles JSON (encrypted) and CSV import/export. Everything runs locally; nothing is uploaded.
 */
class BackupManager(
    private val vaultRepository: VaultRepository,
    private val passwordRepository: PasswordRepository
) {
    companion object {
        const val MIN_BACKUP_PASSWORD_LENGTH = 8
        private const val MAX_IMPORT_VAULTS = 1_000
        private const val MAX_IMPORT_ITEMS = 50_000
        private const val MAX_CSV_ROWS = MAX_IMPORT_ITEMS + 1
        private const val MAX_CSV_COLUMNS = 128
        private const val MAX_VAULT_ID_CHARS = 200
        private const val MAX_VAULT_NAME_CHARS = 40
        private const val MAX_ICON_CHARS = 64
        private const val MAX_TITLE_CHARS = 512
        private const val MAX_USERNAME_CHARS = 1_024
        private const val MAX_PASSWORD_CHARS = 32 * 1_024
        private const val MAX_URL_CHARS = 4 * 1_024
        private const val MAX_NOTE_CHARS = 128 * 1_024
        private const val MAX_TAGS = 100
        private const val MAX_TAG_CHARS = 256
        private const val MAX_CSV_FIELD_CHARS = MAX_NOTE_CHARS
        private const val PREVIEW_SAMPLE_LIMIT = 5
        // Keep encryption and Room's transaction footprint bounded on low-memory devices. A
        // failed batch is retried item by item, so one malformed external record never discards
        // the rest of a large import.
        private const val IMPORT_WRITE_BATCH_SIZE = 200
        private const val NEW_IMPORT_VAULT_PLACEHOLDER = "__new_vault__"
        private const val PENDING_IMPORT_ID_PREFIX = "__pending_import__"
    }

    private data class ImportCandidate(
        val vaultId: String,
        val title: String,
        val username: String,
        val password: String,
        val url: String,
        val tags: List<String>,
        val note: String,
        val favorite: Boolean = false
    ) {
        fun toDecrypted(id: String = "") = DecryptedPassword(
            id = id,
            vaultId = vaultId,
            title = title,
            username = username,
            password = password,
            url = url,
            tags = tags,
            note = note,
            strengthScore = 0,
            createdAt = 0,
            updatedAt = 0,
            favorite = favorite
        )
    }

    private data class PreparedImport(
        val formatLabel: String,
        val targetLabel: String,
        val candidates: List<ImportCandidate>,
        val invalidItems: Int,
        val warnings: List<String>
    )

    private val gson = Gson()
    // JSON import may be launched from both the list and settings flows. Serialise the full
    // read/index/write operation so simultaneous taps cannot calculate duplicates from stale data.
    private val importMutex = Mutex()

    // ---- JSON export (encrypted) ------------------------------------------

    suspend fun buildEncryptedJsonBackup(backupPassword: String): String {
        require(backupPassword.length >= MIN_BACKUP_PASSWORD_LENGTH) {
            "备份密码至少需要 $MIN_BACKUP_PASSWORD_LENGTH 个字符"
        }
        val vaults = vaultRepository.allOnce().map { BackupVault(it.id, it.name, it.icon) }
        require(vaults.size <= MAX_IMPORT_VAULTS) { "密码库数量过多，无法导出" }
        val plainBytes = buildPlainBackupBytes(vaults)
        val salt = CryptoManager.newSalt()
        val kdf = KdfVersions.current()
        val iterations = kdf.iterations
        var key: SecretKey? = null
        var blob: ByteArray? = null
        return try {
            val passwordChars = backupPassword.toCharArray()
            key = try {
                CryptoManager.deriveKey(passwordChars, salt, kdf)
            } finally {
                passwordChars.fill('\u0000')
            }
            val integrityHash = CryptoManager.sha256Hex(plainBytes)
            val encryptedBlob = CryptoManager.encrypt(requireNotNull(key), plainBytes)
            blob = encryptedBlob
            CryptoManager.destroyKey(requireNotNull(key))
            key = null

            val encodedSalt = CryptoManager.encode(salt)
            val encodedBlob = CryptoManager.encode(encryptedBlob)
            val wrapper = EncryptedBackup(
                salt = encodedSalt,
                data = encodedBlob,
                iterations = iterations,
                kdfVersion = kdf.version,
                integrityHash = integrityHash
            )
            val result = gson.toJson(wrapper)
            // Gson serialization is checked without decrypting and materialising the complete
            // plaintext backup a second time. AES-GCM authenticates the payload on import.
            val parsed = gson.fromJson(result, EncryptedBackup::class.java)
            check(
                parsed.format == wrapper.format &&
                    parsed.version == wrapper.version &&
                    parsed.encrypted &&
                    parsed.salt == encodedSalt &&
                    parsed.data == encodedBlob &&
                    parsed.iterations == iterations &&
                    parsed.kdfVersion == kdf.version &&
                    parsed.integrityHash == integrityHash
            ) { "备份封装校验失败" }
            result
        } finally {
            plainBytes.fill(0)
            salt.fill(0)
            blob?.fill(0)
            key?.let(CryptoManager::destroyKey)
        }
    }

    /**
     * Serializes directly to UTF-8 while decrypting one row at a time. This avoids a complete
     * DecryptedPassword list, BackupItem list and immutable UTF-16 JSON String existing together.
     */
    private suspend fun buildPlainBackupBytes(vaults: List<BackupVault>): ByteArray {
        val output = WipeableByteArrayOutputStream()
        val writer = JsonWriter(OutputStreamWriter(output, Charsets.UTF_8))
        return try {
            writer.beginObject()
            writer.name("vaults").beginArray()
            vaults.forEach { vault ->
                writer.beginObject()
                writer.name("id").value(vault.id)
                writer.name("name").value(vault.name)
                writer.name("icon").value(vault.icon)
                writer.endObject()
            }
            writer.endArray()
            writer.name("items").beginArray()
            var itemCount = 0
            passwordRepository.forEachDecrypted { item ->
                itemCount++
                require(itemCount <= MAX_IMPORT_ITEMS) { "密码项目过多，无法导出" }
                writer.beginObject()
                writer.name("vaultId").value(item.vaultId)
                writer.name("title").value(item.title)
                writer.name("username").value(item.username)
                writer.name("password").value(item.password)
                writer.name("url").value(item.url)
                writer.name("tags").beginArray()
                item.tags.forEach(writer::value)
                writer.endArray()
                writer.name("note").value(item.note)
                writer.name("favorite").value(item.favorite)
                writer.endObject()
            }
            writer.endArray()
            writer.endObject()
            writer.flush()
            output.toByteArray()
        } finally {
            runCatching { writer.close() }
            output.wipe()
        }
    }

    private class WipeableByteArrayOutputStream : ByteArrayOutputStream() {
        fun wipe() {
            buf.fill(0)
            reset()
        }
    }

    // ---- JSON import -------------------------------------------------------

    suspend fun previewJsonBackup(content: String, backupPassword: String): ImportPreview {
        val prepared = prepareJsonImport(content, backupPassword)
        return buildPreview(prepared)
    }

    suspend fun importJsonBackup(
        content: String,
        backupPassword: String,
        strategy: ImportConflictStrategy = ImportConflictStrategy.SKIP
    ): ImportResult = importMutex.withLock {
        val backupData: BackupData
        val prepared: PreparedImport
        try {
            // Parse once. Repeating PBKDF2 + AES-GCM merely to retrieve the vault rows makes
            // encrypted imports needlessly slow on older phones.
            backupData = parseEncryptedBackupData(content, backupPassword)
            prepared = prepareJsonImport(backupData)
        } catch (e: CancellationException) {
            throw e
        } catch (e: IllegalArgumentException) {
            return ImportResult(0, 0, 0, listOf(e.message ?: "备份结构无效"))
        } catch (_: Exception) {
            return ImportResult(0, 0, 0, listOf("无法读取备份：密码错误或文件已损坏"))
        }

        val vaultsById = vaultRepository.allOnce().associateBy { it.id }.toMutableMap()
        for (vault in backupData.vaults) {
            if (vault.id in vaultsById) continue
            try {
                val created = VaultEntity(id = vault.id, name = vault.name, icon = vault.icon)
                vaultRepository.insertImported(created)
                vaultsById[vault.id] = created
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Import continues; the candidate-preparation phase already reroutes orphan rows.
            }
        }
        return importPrepared(prepared, strategy)
    }

    // ---- CSV export -------------------------------------------------------

    /**
     * Builds CSV for a vault. [slim] = true emits only the browser-compatible
     * name,url,username,password columns (easy to import into Chrome/Edge); otherwise the full
     * format including note and tags is produced.
     */
    suspend fun buildCsvForVault(vaultId: String, slim: Boolean = false): String {
        val items = passwordRepository.decryptedForVault(vaultId)
        val sb = StringBuilder()
        val header = if (slim) listOf("name", "url", "username", "password")
        else listOf("name", "url", "username", "password", "note", "tags")
        sb.append(CsvUtils.buildRow(header)).append("\n")
        for (item in items) {
            val row = if (slim) listOf(item.title, item.url, item.username, item.password)
            else listOf(item.title, item.url, item.username, item.password, item.note, item.tags.joinToString("|"))
            sb.append(CsvUtils.buildRow(row)).append("\n")
        }
        return sb.toString()
    }

    // ---- CSV import (Chrome / generic) ------------------------------------

    suspend fun previewChromeCsv(content: String, targetVaultId: String): ImportPreview {
        val prepared = prepareCsvImport(content, targetVaultId)
        return buildPreview(prepared)
    }

    suspend fun importChromeCsv(
        content: String,
        targetVaultId: String,
        strategy: ImportConflictStrategy = ImportConflictStrategy.SKIP
    ): ImportResult = importMutex.withLock {
        val prepared = try {
            prepareCsvImport(content, targetVaultId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: IllegalArgumentException) {
            return ImportResult(0, 0, 0, listOf(e.message ?: "CSV 文件无效"))
        } catch (_: Exception) {
            return ImportResult(0, 0, 0, listOf("导入失败，请检查文件后重试"))
        }
        if (prepared.candidates.isEmpty()) {
            return ImportResult(0, 0, prepared.invalidItems, listOf("没有可导入的有效项目"))
        }
        val effectiveTargetVaultId = resolveCsvImportVaultId(
            prepared = prepared,
            requestedVaultId = targetVaultId
        )
        val normalized = prepared.copy(
            candidates = prepared.candidates.map { it.copy(vaultId = effectiveTargetVaultId) }
        )
        return importPrepared(normalized, strategy)
    }

    // ---- Import planning ---------------------------------------------------

    private suspend fun prepareJsonImport(content: String, backupPassword: String): PreparedImport {
        val data = parseEncryptedBackupData(content, backupPassword)
        return prepareJsonImport(data)
    }

    /** Builds the import plan from an already parsed backup to avoid duplicate KDF work. */
    private suspend fun prepareJsonImport(data: BackupData): PreparedImport {
        validateBackup(data)?.let { throw IllegalArgumentException(it) }

        val existingVaults = vaultRepository.allOnce()
        val existingVaultIds = existingVaults.mapTo(linkedSetOf()) { it.id }
        val backupVaultById = data.vaults.associateBy { it.id }
        val effectiveVaultIds = linkedSetOf<String>().apply {
            addAll(existingVaultIds)
            addAll(data.vaults.map { it.id })
        }
        val fallbackVaultId = effectiveVaultIds.firstOrNull()
        val fallbackVaultName = fallbackVaultId?.let { id ->
            existingVaults.firstOrNull { it.id == id }?.name
                ?: backupVaultById[id]?.name
                ?: "默认密码库"
        }.orEmpty()

        var reroutedCount = 0
        var invalidItems = 0
        val candidates = mutableListOf<ImportCandidate>()
        for (item in data.items) {
            coroutineContext.ensureActive()
            val validItem = try {
                isValidImportItem(item)
            } catch (_: Exception) {
                false
            }
            if (!validItem) {
                invalidItems++
                continue
            }
            val targetVaultId = when {
                item.vaultId in effectiveVaultIds -> item.vaultId
                fallbackVaultId != null -> {
                    reroutedCount++
                    fallbackVaultId
                }
                else -> {
                    invalidItems++
                    null
                }
            } ?: continue
            candidates += ImportCandidate(
                vaultId = targetVaultId,
                title = item.title,
                username = item.username,
                password = item.password,
                url = item.url,
                tags = item.tags,
                note = item.note,
                favorite = item.favorite
            )
        }

        val warnings = buildList {
            if (reroutedCount > 0) add("${reroutedCount} 项无法匹配原密码库，已改为导入到“$fallbackVaultName”")
        }
        val targetLabel = when (effectiveVaultIds.size) {
            0 -> "无可用密码库"
            1 -> fallbackVaultName
            else -> "多个密码库"
        }
        return PreparedImport("加密备份 JSON", targetLabel, candidates, invalidItems, warnings)
    }

    private suspend fun prepareCsvImport(content: String, targetVaultId: String): PreparedImport {
        val rows = CsvUtils.parse(
            text = content,
            maxRows = MAX_CSV_ROWS,
            maxColumns = MAX_CSV_COLUMNS,
            maxFieldChars = MAX_CSV_FIELD_CHARS
        )
        if (rows.isEmpty()) throw IllegalArgumentException("CSV 文件为空")
        if (rows.size > MAX_CSV_ROWS) throw IllegalArgumentException("CSV 中的项目数量过多")

        val existingVault = targetVaultId.takeIf { it.isNotBlank() }?.let { vaultRepository.getById(it) }
        val effectiveVaultId = existingVault?.id ?: targetVaultId.ifBlank { NEW_IMPORT_VAULT_PLACEHOLDER }
        val targetLabel = existingVault?.name ?: "已导入（将新建）"

        val header = rows.first().map { normalizeHeader(it) }
        val nameIdx = header.indexOfAny("name", "title", "网站名称", "名称", "标题")
        val urlIdx = header.indexOfAny("url", "origin_url", "action_url", "login_url", "website", "site", "网址", "网站")
        val userIdx = header.indexOfAny("username", "user", "login", "email", "login_username", "账号", "用户名", "邮箱")
        val passIdx = header.indexOfAny("password", "pass", "login_password", "密码")
        val noteIdx = header.indexOfAny("note", "notes", "备注")
        val tagsIdx = header.indexOfAny("tags", "tag", "标签")

        if (passIdx < 0) throw IllegalArgumentException("CSV 中缺少 “password” 列")

        var invalidItems = 0
        val candidates = mutableListOf<ImportCandidate>()
        for (row in rows.drop(1)) {
            coroutineContext.ensureActive()
            try {
                fun at(index: Int) = if (index in row.indices) row[index].trim() else ""
                val title = at(nameIdx).ifEmpty { at(urlIdx).ifEmpty { "已导入" } }
                val username = at(userIdx)
                val password = at(passIdx)
                val url = at(urlIdx)
                val note = at(noteIdx)
                val tags = at(tagsIdx).split("|", ",").map { it.trim() }.filter { it.isNotEmpty() }
                if (password.isEmpty() && username.isEmpty() ||
                    !isValidCandidateFields(title, username, password, url, tags, note)
                ) {
                    invalidItems++
                    continue
                }
                candidates += ImportCandidate(
                    vaultId = effectiveVaultId,
                    title = title,
                    username = username,
                    password = password,
                    url = url,
                    tags = tags,
                    note = note
                )
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                invalidItems++
            }
        }

        val warnings = if (existingVault == null) listOf("当前将导入到新建密码库“已导入”") else emptyList()
        return PreparedImport("浏览器 CSV", targetLabel, candidates, invalidItems, warnings)
    }

    private suspend fun buildPreview(prepared: PreparedImport): ImportPreview {
        val existingByVault = existingIndexByVault(prepared.candidates.map { it.vaultId }.distinct())
        var newItems = 0
        var duplicateItems = 0
        val sampleTitles = mutableListOf<String>()

        for ((vaultId, vaultItems) in prepared.candidates.groupBy { it.vaultId }) {
            val seen = existingByVault[vaultId]
                ?.mapValues { (_, value) -> value.toMutableList() }
                ?.toMutableMap()
                ?: mutableMapOf()
            for (candidate in vaultItems) {
                coroutineContext.ensureActive()
                if (findMatchingExisting(seen, candidate) != null) {
                    duplicateItems++
                } else {
                    indexCandidate(seen, candidate)
                    newItems++
                    if (sampleTitles.size < PREVIEW_SAMPLE_LIMIT) {
                        sampleTitles += candidate.title.ifBlank { candidate.url.ifBlank { "未命名项目" } }
                    }
                }
            }
        }

        return ImportPreview(
            formatLabel = prepared.formatLabel,
            targetLabel = prepared.targetLabel,
            totalItems = prepared.candidates.size + prepared.invalidItems,
            newItems = newItems,
            duplicateItems = duplicateItems,
            invalidItems = prepared.invalidItems,
            sampleTitles = sampleTitles,
            warnings = prepared.warnings
        )
    }

    private suspend fun importPrepared(
        prepared: PreparedImport,
        strategy: ImportConflictStrategy
    ): ImportResult {
        var imported = 0
        var skipped = 0
        var failed = prepared.invalidItems
        var updated = 0
        val errors = mutableListOf<String>()

        val candidatesByVault = prepared.candidates.groupBy { it.vaultId }
        for ((vaultId, vaultCandidates) in candidatesByVault) {
            try {
                val existingByKey = buildCandidateIndex(passwordRepository.decryptedForVaultSkippingCorrupt(vaultId))

                when (strategy) {
                    ImportConflictStrategy.SKIP -> {
                        val seen = existingByKey
                            .mapValues { (_, value) -> value.toMutableList() }
                            .toMutableMap()
                        val toInsert = mutableListOf<DecryptedPassword>()
                        for (candidate in vaultCandidates) {
                            coroutineContext.ensureActive()
                            if (findMatchingExisting(seen, candidate) != null) {
                                skipped++
                            } else {
                                toInsert += candidate.toDecrypted()
                                indexCandidate(seen, candidate)
                            }
                        }
                        imported += insertCandidates(vaultId, toInsert, errors).also { if (it < toInsert.size) failed += toInsert.size - it }
                    }

                    ImportConflictStrategy.KEEP_BOTH -> {
                        val toInsert = vaultCandidates.map {
                            coroutineContext.ensureActive()
                            it.toDecrypted()
                        }
                        imported += insertCandidates(vaultId, toInsert, errors).also { if (it < toInsert.size) failed += toInsert.size - it }
                    }

                    ImportConflictStrategy.OVERWRITE -> {
                        val seen = existingByKey
                            .mapValues { (_, value) -> value.toMutableList() }
                            .toMutableMap()
                        val pendingCreates = linkedMapOf<String, DecryptedPassword>()
                        var tempCounter = 0

                        for (candidate in vaultCandidates) {
                            coroutineContext.ensureActive()
                            val existing = findMatchingExisting(seen, candidate)
                            if (existing != null) {
                                if (existing.id.startsWith(PENDING_IMPORT_ID_PREFIX)) {
                                    // The later duplicate replaces the pending row; account for the
                                    // superseded input so result totals still match the preview.
                                    skipped++
                                    val replacement = candidate.toDecrypted(existing.id)
                                    pendingCreates[existing.id] = replacement
                                    removeIndexedExisting(seen, existing.id)
                                    indexExisting(seen, replacement)
                                } else {
                                    try {
                                        passwordRepository.save(
                                            id = existing.id,
                                            vaultId = vaultId,
                                            title = candidate.title,
                                            username = candidate.username,
                                            password = candidate.password,
                                            url = candidate.url,
                                            tags = candidate.tags,
                                            note = candidate.note,
                                            favorite = candidate.favorite
                                        )
                                        updated++
                                        removeIndexedExisting(seen, existing.id)
                                        indexExisting(seen, candidate.toDecrypted(existing.id))
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (_: Exception) {
                                        failed++
                                        errors += "部分项目覆盖失败"
                                    }
                                }
                            } else {
                                val pendingId = "$PENDING_IMPORT_ID_PREFIX:$vaultId:${tempCounter++}"
                                val pending = candidate.toDecrypted(pendingId)
                                pendingCreates[pendingId] = pending
                                indexExisting(seen, pending)
                            }
                        }
                        val toInsert = pendingCreates.values.toList()
                        imported += insertCandidates(vaultId, toInsert, errors).also { if (it < toInsert.size) failed += toInsert.size - it }
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                failed += vaultCandidates.size
                errors += "密码库导入失败"
            }
        }

        return ImportResult(
            imported = imported,
            skippedDuplicates = skipped,
            failed = failed,
            errors = errors,
            updated = updated
        )
    }

    private suspend fun insertCandidates(
        vaultId: String,
        items: List<DecryptedPassword>,
        errors: MutableList<String>
    ): Int {
        if (items.isEmpty()) return 0
        var inserted = 0
        for (batch in items.chunked(IMPORT_WRITE_BATCH_SIZE)) {
            try {
                inserted += passwordRepository.importDecrypted(vaultId, batch)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Room's batch insert is transactional: retry this small batch one by one so a
                // malformed external row cannot discard its valid neighbours.
                batch.forEach { item ->
                    try {
                        passwordRepository.importDecrypted(vaultId, listOf(item))
                        inserted++
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        // Counted by the caller; never expose imported credential content here.
                    }
                }
            }
        }
        if (inserted < items.size) errors += "部分项目导入失败"
        return inserted
    }

    private suspend fun existingIndexByVault(
        vaultIds: List<String>
    ): Map<String, Map<String, List<DecryptedPassword>>> {
        val result = mutableMapOf<String, Map<String, List<DecryptedPassword>>>()
        for (vaultId in vaultIds.distinct().filterNot { it == NEW_IMPORT_VAULT_PLACEHOLDER }) {
            result[vaultId] = buildCandidateIndex(passwordRepository.decryptedForVaultSkippingCorrupt(vaultId))
        }
        return result
    }

    private suspend fun resolveCsvImportVaultId(
        prepared: PreparedImport,
        requestedVaultId: String
    ): String {
        val preparedVaultId = prepared.candidates.firstOrNull()?.vaultId.orEmpty()
        if (preparedVaultId.isNotBlank() &&
            preparedVaultId != NEW_IMPORT_VAULT_PLACEHOLDER &&
            vaultRepository.getById(preparedVaultId) != null
        ) {
            return preparedVaultId
        }
        if (requestedVaultId.isNotBlank() && vaultRepository.getById(requestedVaultId) != null) {
            return requestedVaultId
        }
        return vaultRepository.create("已导入", "lock").id
    }

    /**
     * The JSON-backup UI is exclusively for encrypted Offline Vault wrappers. Keeping the wrapper
     * shape check ahead of Gson deserialization prevents ordinary transfer JSON from being treated
     * as a password-protected backup merely because model defaults happen to look valid.
     */
    private fun parseEncryptedBackupData(content: String, backupPassword: String): BackupData {
        val wrapperObject = try {
            JsonParser.parseString(content).takeIf { it.isJsonObject }?.asJsonObject
        } catch (_: Exception) {
            null
        } ?: throw IllegalArgumentException("这不是加密备份文件")
        require(
            wrapperObject.has("format") &&
                wrapperObject.has("encrypted") &&
                wrapperObject.has("salt") &&
                wrapperObject.has("data")
        ) { "这不是加密备份文件" }
        val wrapper = gson.fromJson(wrapperObject, EncryptedBackup::class.java)
            ?: throw IllegalArgumentException("加密备份格式无效")
        require(wrapper.format == "offline-vault-backup" && wrapper.encrypted) {
            "这不是加密备份文件"
        }
        require(wrapper.salt.isNotBlank() && wrapper.data.isNotBlank()) {
            "加密备份缺少必要数据"
        }

        val salt = CryptoManager.decode(wrapper.salt)
        try {
            val encryptedBytes = CryptoManager.decode(wrapper.data)
            try {
                val iterations = CryptoManager.requireValidIterations(
                    if (wrapper.iterations > 0) wrapper.iterations
                    else CryptoManager.LEGACY_PBKDF2_ITERATIONS
                )
                val kdf = KdfVersions.stored(wrapper.kdfVersion, iterations)
                val passwordChars = backupPassword.toCharArray()
                val key = try {
                    CryptoManager.deriveKey(passwordChars, salt, kdf)
                } finally {
                    passwordChars.fill('\u0000')
                }
                val plainBytes = try {
                    CryptoManager.decrypt(key, encryptedBytes)
                } finally {
                    CryptoManager.destroyKey(key)
                }
                if (wrapper.integrityHash.isNotBlank() &&
                    !wrapper.integrityHash.equals(CryptoManager.sha256Hex(plainBytes), ignoreCase = true)
                ) {
                    throw IllegalArgumentException("备份完整性校验失败")
                }
                return try {
                    InputStreamReader(
                        ByteArrayInputStream(plainBytes),
                        Charsets.UTF_8
                    ).use { reader ->
                        gson.fromJson(reader, BackupData::class.java)
                            ?: throw IllegalArgumentException("备份为空或格式无效")
                    }
                } finally {
                    plainBytes.fill(0)
                }
            } finally {
                encryptedBytes.fill(0)
            }
        } finally {
            salt.fill(0)
        }
    }

    private fun validateBackup(data: BackupData): String? = try {
        when {
            data.vaults.size > MAX_IMPORT_VAULTS -> "备份中的密码库数量过多"
            data.items.size > MAX_IMPORT_ITEMS -> "备份中的项目数量过多"
            data.vaults.map { it.id }.distinct().size != data.vaults.size -> "备份中存在重复的密码库标识"
            data.vaults.any {
                it.id.isBlank() ||
                    it.id.length > MAX_VAULT_ID_CHARS ||
                    it.name.isBlank() ||
                    it.name.length > MAX_VAULT_NAME_CHARS ||
                    it.icon.length > MAX_ICON_CHARS
            } -> "备份中包含无效的密码库"
            else -> null
        }
    } catch (_: Exception) {
        // Gson can assign null to Kotlin non-null properties in malformed external JSON.
        "备份结构无效"
    }

    private fun DecryptedPassword.matchKeys(): Set<String> =
        buildMatchKeys(title, username, password, url)

    private fun ImportCandidate.matchKeys(): Set<String> =
        buildMatchKeys(title, username, password, url)

    private fun buildCandidateIndex(items: List<DecryptedPassword>): MutableMap<String, MutableList<DecryptedPassword>> {
        val index = linkedMapOf<String, MutableList<DecryptedPassword>>()
        items.forEach { indexExisting(index, it) }
        return index
    }

    private fun indexExisting(
        index: MutableMap<String, MutableList<DecryptedPassword>>,
        item: DecryptedPassword
    ) {
        item.matchKeys().forEach { key ->
            index.getOrPut(key) { mutableListOf() }.apply {
                if (none { it.id == item.id }) add(item)
            }
        }
    }

    private fun removeIndexedExisting(
        index: MutableMap<String, MutableList<DecryptedPassword>>,
        id: String
    ) {
        val keysToRemove = mutableListOf<String>()
        index.forEach { (key, value) ->
            value.removeAll { it.id == id }
            if (value.isEmpty()) keysToRemove += key
        }
        keysToRemove.forEach(index::remove)
    }

    private fun indexCandidate(
        index: MutableMap<String, MutableList<DecryptedPassword>>,
        candidate: ImportCandidate
    ) {
        val temp = candidate.toDecrypted()
        candidate.matchKeys().forEach { key ->
            index.getOrPut(key) { mutableListOf() }.add(temp)
        }
    }

    private fun findMatchingExisting(
        index: Map<String, List<DecryptedPassword>>,
        candidate: ImportCandidate
    ): DecryptedPassword? {
        val keyed = candidate.matchKeys()
            .flatMap { index[it].orEmpty() }
            .distinctBy { it.id.ifBlank { "candidate:${System.identityHashCode(it)}" } }
        return keyed.firstOrNull { isSameCredential(it, candidate) }
    }

    private fun isSameCredential(existing: DecryptedPassword, candidate: ImportCandidate): Boolean {
        val existingUser = existing.username.normalizedUser()
        val candidateUser = candidate.username.normalizedUser()
        if (existingUser.isNotEmpty() && candidateUser.isNotEmpty() && existingUser != candidateUser) return false

        val existingHost = comparableHost(existing.url)
        val candidateHost = comparableHost(candidate.url)
        if (existingHost != null && candidateHost != null &&
            existingHost == candidateHost &&
            (existingUser.isNotEmpty() || candidateUser.isNotEmpty())
        ) {
            return true
        }

        val existingTitle = existing.title.normalizedTitle()
        val candidateTitle = candidate.title.normalizedTitle()
        if (existingTitle.isNotEmpty() && candidateTitle.isNotEmpty()) {
            if (existingTitle == candidateTitle) return true
            if (existingTitle.contains(candidateTitle) || candidateTitle.contains(existingTitle)) return true
        }

        val sharedTokens = identifierTokens(existing.title, existing.url)
            .intersect(identifierTokens(candidate.title, candidate.url))
        if (sharedTokens.isNotEmpty() && (existingUser.isNotEmpty() || candidateUser.isNotEmpty())) return true

        return existingUser.isEmpty() && candidateUser.isEmpty() &&
            existing.password.trim().isNotEmpty() &&
            existing.password.trim() == candidate.password.trim() &&
            existingHost != null &&
            existingHost == candidateHost
    }

    private fun buildMatchKeys(title: String, username: String, password: String, url: String): Set<String> {
        val user = username.normalizedUser()
        val host = comparableHost(url)
        val normalizedTitle = title.normalizedTitle()
        val tokens = identifierTokens(title, url)
        return buildSet {
            if (user.isNotEmpty() && host != null) add("host:$host|user:$user")
            if (user.isNotEmpty() && normalizedTitle.isNotEmpty()) add("title:$normalizedTitle|user:$user")
            if (user.isNotEmpty()) tokens.forEach { add("token:$it|user:$user") }
            if (user.isEmpty() && host != null && normalizedTitle.isNotEmpty()) add("host:$host|title:$normalizedTitle")
            if (user.isEmpty() && host != null && password.trim().isNotEmpty()) add("host:$host|empty-user")
        }
    }

    private fun comparableHost(url: String): String? =
        OriginMatcher.hostFromUrl(url)?.removePrefix("www.")

    private fun normalizeHeader(value: String): String =
        value.trim().trim('\uFEFF').lowercase(Locale.ROOT).replace(" ", "_").replace("-", "_")

    private fun List<String>.indexOfAny(vararg candidates: String): Int {
        val wanted = candidates.map(::normalizeHeader).toSet()
        return indexOfFirst { it in wanted }
    }

    private fun String.normalizedUser(): String = trim().lowercase(Locale.ROOT)

    private fun String.normalizedTitle(): String =
        lowercase(Locale.ROOT)
            .replace(Regex("[^\\p{L}\\p{N}]+"), " ")
            .trim()
            .replace(Regex("\\s+"), " ")

    private fun identifierTokens(title: String, url: String): Set<String> {
        val stopWords = setOf("www", "com", "net", "org", "app", "login", "secure", "account", "online", "site", "web")
        val titleTokens = title.normalizedTitle()
            .split(' ')
            .filter { it.length >= 3 && it !in stopWords }
        val hostTokens = comparableHost(url)
            ?.split('.', '-')
            ?.filter { it.length >= 3 && it !in stopWords }
            .orEmpty()
        return (titleTokens + hostTokens).toSet()
    }

    private fun isValidImportItem(item: BackupItem): Boolean = try {
        item.vaultId.isNotBlank() &&
            item.vaultId.length <= MAX_VAULT_ID_CHARS &&
            isValidCandidateFields(
                item.title,
                item.username,
                item.password,
                item.url,
                item.tags,
                item.note
            )
    } catch (_: Exception) {
        // Gson can materialise null into Kotlin non-null properties from hostile JSON.
        false
    }

    private fun isValidCandidateFields(
        title: String,
        username: String,
        password: String,
        url: String,
        tags: List<String>,
        note: String
    ): Boolean =
        title.length <= MAX_TITLE_CHARS &&
            username.length <= MAX_USERNAME_CHARS &&
            password.length <= MAX_PASSWORD_CHARS &&
            url.length <= MAX_URL_CHARS &&
            note.length <= MAX_NOTE_CHARS &&
            tags.size <= MAX_TAGS &&
            tags.all { it.length <= MAX_TAG_CHARS }
}
