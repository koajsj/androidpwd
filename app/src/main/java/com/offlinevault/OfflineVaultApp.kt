package com.offlinevault

import android.app.Application
import android.widget.Toast
import com.offlinevault.autofill.PendingAutofillSave
import com.offlinevault.security.SessionManager
import com.offlinevault.utils.ClipboardHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class OfflineVaultApp : Application() {

    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        // Re-arm a best-effort clipboard expiry if Android reclaimed the process before its
        // in-memory timer ran. Only a random marker and deadline are persisted, never the secret.
        ClipboardHelper.restorePendingSensitiveClear(this)
        applicationScope.launch {
            SessionManager.unlocked.filter { it }.collect {
                var recoveryMaterialMigrationFailed = false
                withContext(Dispatchers.IO) {
                    try {
                        // Remove the legacy non-biometric device envelope while its key is still
                        // available. A future Keystore reset must not invalidate master-password
                        // or mnemonic recovery of the vault.
                        container.keyManager.migrateLegacyDeviceWrappedMaterial()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        // The current master-password session remains usable. Make the recovery
                        // degradation visible below rather than silently claiming it is healthy.
                        recoveryMaterialMigrationFailed = true
                    }
                    try {
                        container.vaultRepository.migrateLegacyMetadata()
                        container.passwordRepository.migrateLegacyMetadata()
                        // Permanently remove recycle-bin items past their retention window.
                        container.passwordRepository.purgeExpiredTrash()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        // Maintenance is best-effort. A single damaged credential is already
                        // isolated by repository list/detail flows; locking the whole vault here
                        // would make the remaining recoverable records permanently inaccessible.
                    }
                }
                // The activity may have been backgrounded while maintenance was running.
                if (!SessionManager.isUnlocked) {
                    return@collect
                }
                if (recoveryMaterialMigrationFailed) {
                    Toast.makeText(
                        this@OfflineVaultApp,
                        "恢复材料迁移未完成。请尽快创建加密备份，并在设置中重新设置恢复方式。",
                        Toast.LENGTH_LONG
                    ).show()
                }
                val integrity = withContext(Dispatchers.IO) {
                    runCatching { container.integrityChecker.inspect() }.getOrNull()
                }
                if (integrity?.databaseHealthy == false) {
                    SessionManager.lock()
                    Toast.makeText(
                        this@OfflineVaultApp,
                        "密码库结构校验失败，已锁定以保护数据。请使用加密备份恢复。",
                        Toast.LENGTH_LONG
                    ).show()
                    return@collect
                }
                if (integrity?.hasEncryptedDataIssues == true) {
                    Toast.makeText(
                        this@OfflineVaultApp,
                        "发现损坏或被修改的密码记录，已隔离异常项目。",
                        Toast.LENGTH_LONG
                    ).show()
                }
                persistPendingAutofillSave()
            }
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) {
            SessionManager.lock()
        }
    }

    /** Saves a credential captured by autofill while the vault was locked, once it unlocks. */
    private suspend fun persistPendingAutofillSave() {
        val capture = PendingAutofillSave.consume() ?: return
        val saved = withContext(Dispatchers.IO) {
            try {
                val vaultId = container.vaultRepository.ensureDefault().id
                container.passwordRepository.upsertFromAutofill(
                    vaultId, capture.identifier, capture.username, capture.password
                )
                true
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                false
            }
        }
        if (saved) {
            Toast.makeText(this@OfflineVaultApp, "已将账号保存到密码库", Toast.LENGTH_SHORT).show()
        } else {
            // Keep the encrypted in-memory capture for one later unlock. If it cannot be retained
            // (for example, the Keystore is unavailable), it has already been safely dropped.
            PendingAutofillSave.set(capture)
        }
    }
}
