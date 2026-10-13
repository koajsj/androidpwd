package com.offlinevault.data.repository

import com.offlinevault.data.dao.VaultDao
import com.offlinevault.data.model.VaultEntity
import com.offlinevault.security.EncryptedField
import com.offlinevault.security.SessionManager
import com.offlinevault.security.VaultLockedException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import java.util.UUID

class VaultRepository(private val vaultDao: VaultDao) {

    // Vault names are encrypted metadata. Decrypt the complete switcher list away from Compose's
    // main thread so a large multi-vault import does not hitch navigation or settings rendering.
    fun allVaults(): Flow<List<VaultEntity>> =
        vaultDao.getAllVaults()
            .combine(SessionManager.unlocked) { rows, unlocked ->
                if (!unlocked) return@combine emptyList()
                try {
                    SessionManager.withActiveSession { rows.map(::decrypt) }
                } catch (_: VaultLockedException) {
                    emptyList()
                }
            }
            .flowOn(Dispatchers.Default)

    suspend fun getById(id: String): VaultEntity? =
        SessionManager.withActiveSession { vaultDao.getById(id)?.let(::decrypt) }

    suspend fun allOnce(): List<VaultEntity> =
        SessionManager.withActiveSession {
            vaultDao.getAllVaultsOnce().map(::decrypt)
        }

    suspend fun create(name: String, icon: String): VaultEntity =
        DatabaseWriteGate.withWrite {
            SessionManager.withActiveSession {
                val id = UUID.randomUUID().toString()
                val vault = VaultEntity(
                    id = id,
                    name = EncryptedField.encrypt(requireVaultName(name), nameContext(id)),
                    icon = icon
                )
                vaultDao.insert(vault)
                decrypt(vault)
            }
        }

    /** Renames a vault without exposing its display name in the database. */
    suspend fun rename(id: String, name: String): VaultEntity? =
        DatabaseWriteGate.withWrite {
            SessionManager.withActiveSession {
                val existing = vaultDao.getById(id) ?: return@withActiveSession null
                val updated = existing.copy(
                    name = EncryptedField.encrypt(requireVaultName(name), nameContext(id)),
                    updatedAt = System.currentTimeMillis()
                )
                vaultDao.update(updated)
                decrypt(updated)
            }
        }

    /**
     * Deletes one vault and its credentials through Room's foreign-key cascade. At least one
     * vault is always retained, so callers never end up with an unusable empty destination.
     */
    suspend fun deleteKeepingOne(id: String): VaultDeleteResult = DatabaseWriteGate.withWrite {
        SessionManager.withActiveSession {
            val vaults = vaultDao.getAllVaultsOnce()
            val target = vaults.firstOrNull { it.id == id } ?:
                return@withActiveSession VaultDeleteResult.NotFound
            if (vaults.size <= 1) return@withActiveSession VaultDeleteResult.LastVault

            vaultDao.delete(target)
            val fallback = vaults.first { it.id != id }
            VaultDeleteResult.Deleted(decrypt(fallback))
        }
    }

    suspend fun touch(vaultId: String) {
        DatabaseWriteGate.withWrite {
            SessionManager.withActiveSession {
                vaultDao.getById(vaultId)?.let {
                    vaultDao.update(it.copy(updatedAt = System.currentTimeMillis()))
                }
            }
        }
    }

    /** Ensures there is always at least one vault to put credentials into. */
    suspend fun ensureDefault(): VaultEntity = DatabaseWriteGate.withWrite {
        SessionManager.withActiveSession {
            vaultDao.firstVault()?.let { return@withActiveSession decrypt(it) }
            val id = UUID.randomUUID().toString()
            val vault = VaultEntity(
                id = id,
                name = EncryptedField.encrypt("个人", nameContext(id)),
                icon = "person"
            )
            vaultDao.insert(vault)
            decrypt(vault)
        }
    }

    suspend fun insertImported(vault: VaultEntity) {
        DatabaseWriteGate.withWrite {
            SessionManager.withActiveSession {
                vaultDao.insert(vault.copy(name = EncryptedField.encrypt(vault.name, nameContext(vault.id))))
            }
        }
    }

    suspend fun migrateLegacyMetadata() = DatabaseWriteGate.withWrite {
        SessionManager.withActiveSession {
            vaultDao.getAllVaultsOnce().forEach { row ->
                // Isolate a single damaged vault name the same way credential migration isolates a
                // damaged record: one bad row must not abort migration of the rest (and, in turn,
                // the password migration that runs after this) on every unlock.
                try {
                    if (!EncryptedField.isContextBound(row.name)) {
                        val migratedName = EncryptedField.migrate(row.name, nameContext(row.id))
                        vaultDao.migrateNameIfUnchanged(row.id, row.name, migratedName)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: VaultLockedException) {
                    // The vault locked mid-migration: stop entirely rather than skipping rows.
                    throw e
                } catch (_: Exception) {
                    // The unlock-time integrity sweep reports and the UI isolates this vault.
                }
            }
        }
    }

    private fun decrypt(vault: VaultEntity): VaultEntity = try {
            vault.copy(name = EncryptedField.decrypt(vault.name, nameContext(vault.id)))
        } catch (e: VaultLockedException) {
            throw e
        } catch (_: Exception) {
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

    private fun nameContext(id: String): String = "vault:$id:name"
}

sealed interface VaultDeleteResult {
    data class Deleted(val fallbackVault: VaultEntity) : VaultDeleteResult
    data object LastVault : VaultDeleteResult
    data object NotFound : VaultDeleteResult
}
