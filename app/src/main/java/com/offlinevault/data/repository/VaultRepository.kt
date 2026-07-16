package com.offlinevault.data.repository

import com.offlinevault.data.dao.VaultDao
import com.offlinevault.data.model.VaultEntity
import com.offlinevault.security.EncryptedField
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class VaultRepository(private val vaultDao: VaultDao) {

    // Serialises ensureDefault() so two concurrent callers (e.g. the password list loading while an
    // autofill save unlocks) can't both pass the "no vault yet" check and create duplicate defaults.
    private val ensureDefaultMutex = Mutex()

    // Vault names are encrypted metadata. Decrypt the complete switcher list away from Compose's
    // main thread so a large multi-vault import does not hitch navigation or settings rendering.
    fun allVaults(): Flow<List<VaultEntity>> =
        vaultDao.getAllVaults()
            .map { rows -> rows.map(::decrypt) }
            .flowOn(Dispatchers.Default)

    suspend fun getById(id: String): VaultEntity? = vaultDao.getById(id)?.let(::decrypt)

    suspend fun allOnce(): List<VaultEntity> = vaultDao.getAllVaultsOnce().map(::decrypt)

    suspend fun create(name: String, icon: String): VaultEntity {
        val vault = VaultEntity(name = EncryptedField.encrypt(requireVaultName(name)), icon = icon)
        vaultDao.insert(vault)
        return decrypt(vault)
    }

    /** Renames a vault without exposing its display name in the database. */
    suspend fun rename(id: String, name: String): VaultEntity? {
        val existing = vaultDao.getById(id) ?: return null
        val updated = existing.copy(
            name = EncryptedField.encrypt(requireVaultName(name)),
            updatedAt = System.currentTimeMillis()
        )
        vaultDao.update(updated)
        return decrypt(updated)
    }

    /**
     * Deletes one vault and its credentials through Room's foreign-key cascade. At least one
     * vault is always retained, so callers never end up with an unusable empty destination.
     */
    suspend fun deleteKeepingOne(id: String): VaultDeleteResult = ensureDefaultMutex.withLock {
        val vaults = vaultDao.getAllVaultsOnce()
        val target = vaults.firstOrNull { it.id == id } ?: return@withLock VaultDeleteResult.NotFound
        if (vaults.size <= 1) return@withLock VaultDeleteResult.LastVault

        vaultDao.delete(target)
        val fallback = vaults.first { it.id != id }
        VaultDeleteResult.Deleted(decrypt(fallback))
    }

    suspend fun touch(vaultId: String) {
        vaultDao.getById(vaultId)?.let {
            vaultDao.update(it.copy(updatedAt = System.currentTimeMillis()))
        }
    }

    /** Ensures there is always at least one vault to put credentials into. */
    suspend fun ensureDefault(): VaultEntity = ensureDefaultMutex.withLock {
        vaultDao.firstVault()?.let { return@withLock decrypt(it) }
        val vault = VaultEntity(name = EncryptedField.encrypt("个人"), icon = "person")
        vaultDao.insert(vault)
        decrypt(vault)
    }

    suspend fun insertImported(vault: VaultEntity) {
        vaultDao.insert(vault.copy(name = EncryptedField.encrypt(vault.name)))
    }

    suspend fun migrateLegacyMetadata() {
        vaultDao.getAllVaultsOnce().forEach { row ->
            if (!EncryptedField.isEncrypted(row.name)) {
                vaultDao.update(row.copy(name = EncryptedField.encrypt(row.name)))
            }
        }
    }

    private fun decrypt(vault: VaultEntity): VaultEntity =
        runCatching {
            vault.copy(name = EncryptedField.decrypt(vault.name))
        }.getOrElse {
            // Keep the vault reachable even if its encrypted display name is damaged; credentials
            // inside it remain independently encrypted and can still be listed/imported/exported.
            vault.copy(name = "密码库")
        }

    private fun requireVaultName(value: String): String {
        val name = value.trim()
        require(name.isNotEmpty()) { "密码库名称不能为空" }
        require(name.length <= MAX_NAME_LENGTH) { "密码库名称不能超过 $MAX_NAME_LENGTH 个字符" }
        return name
    }

    companion object {
        const val MAX_NAME_LENGTH = 40
    }
}

sealed interface VaultDeleteResult {
    data class Deleted(val fallbackVault: VaultEntity) : VaultDeleteResult
    data object LastVault : VaultDeleteResult
    data object NotFound : VaultDeleteResult
}
