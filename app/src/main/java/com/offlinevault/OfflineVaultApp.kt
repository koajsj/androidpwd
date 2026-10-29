package com.offlinevault

import android.app.Application
import android.widget.Toast
import com.offlinevault.autofill.PendingAutofillSave
import com.offlinevault.security.SessionManager
import com.offlinevault.data.repository.DatabaseWriteGate
import com.offlinevault.data.repository.DatabaseWriteOutcomeException
import androidx.room.withTransaction
import com.offlinevault.utils.ClipboardHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class OfflineVaultApp : Application() {

    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val autofillSaveMutex = Mutex()

    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        // Re-arm a best-effort clipboard expiry if Android reclaimed the process before its
        // in-memory timer ran. Only a random marker and deadline are persisted, never the secret.
        ClipboardHelper.restorePendingSensitiveClear(this)
        applicationScope.launch {
            SessionManager.activeGeneration.collectLatest { generation ->
                if (generation == null) return@collectLatest
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
                        container.passwordRepository.migrateLegacyEncryption()
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
                if (!SessionManager.isUnlocked || SessionManager.sessionGeneration != generation) {
                    return@collectLatest
                }
                if (recoveryMaterialMigrationFailed) {
                    Toast.makeText(
                        this@OfflineVaultApp,
                        "恢复材料迁移未完成。请尽快创建加密备份，并在设置中重新设置恢复方式。",
                        Toast.LENGTH_LONG
                    ).show()
                }
                val integrity = withContext(Dispatchers.IO) {
                    try {
                        Result.success(container.integrityChecker.inspect())
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Result.failure(e)
                    }
                }
                // The activity may have been backgrounded (and the session locked) while the
                // integrity check was running; nothing left to protect.
                if (!SessionManager.isUnlocked || SessionManager.sessionGeneration != generation) {
                    return@collectLatest
                }
                val report = integrity.getOrNull()
                if (integrity.isFailure) {
                    // Fail closed: an integrity check that could not complete is NOT evidence the
                    // database is healthy. Lock rather than continue against an unverified vault.
                    SessionManager.lock()
                    Toast.makeText(
                        this@OfflineVaultApp,
                        "无法完成密码库结构校验，已锁定以保护数据。请重试解锁或使用加密备份恢复。",
                        Toast.LENGTH_LONG
                    ).show()
                    return@collectLatest
                }
                if (report?.databaseHealthy == false) {
                    SessionManager.lock()
                    Toast.makeText(
                        this@OfflineVaultApp,
                        "密码库结构校验失败，已锁定以保护数据。请使用加密备份恢复。",
                        Toast.LENGTH_LONG
                    ).show()
                    return@collectLatest
                }
                if (report?.hasEncryptedDataIssues == true) {
                    Toast.makeText(
                        this@OfflineVaultApp,
                        "发现未完成迁移、损坏或被修改的密码记录，已隔离异常项目。",
                        Toast.LENGTH_LONG
                    ).show()
                }
                savePendingAutofillCaptures(generation)
            }
        }
    }

    /** Main-thread entry: live and post-unlock saves share a queue; database work switches to IO. */
    suspend fun savePendingAutofillCaptures(generation: Long): Boolean =
        autofillSaveMutex.withLock {
            persistPendingAutofillSave(generation)
        }

    private suspend fun writeAutofillCapture(capture: PendingAutofillSave.Capture, generation: Long) {
        withContext(Dispatchers.IO) {
            DatabaseWriteGate.withTransaction(transaction = { action -> container.database.withTransaction { action() } }) {
                SessionManager.requireActiveSession(generation)
                val vaultId = container.vaultRepository.ensureDefault().id
                container.passwordRepository.upsertFromAutofill(
                    vaultId, capture.identifier, capture.username, capture.password
                )
            }
            // Set before returning across a cancellable dispatcher boundary.
            capture.receipt.saved = true
        }
    }

    /** Caller owns autofillSaveMutex. A failed deferred save blocks newer direct writes. */
    private suspend fun persistPendingAutofillSave(generation: Long): Boolean {
        while (SessionManager.isUnlocked && SessionManager.sessionGeneration == generation) {
            val capture = PendingAutofillSave.consume() ?: return true
            val saved = try {
                writeAutofillCapture(capture, generation)
                capture.receipt.saved = true
                true
            } catch (e: CancellationException) {
                if (!capture.receipt.saved) retainPendingAutofillSave(capture)
                throw e
            } catch (e: DatabaseWriteOutcomeException) {
                if (e.committed) {
                    capture.receipt.saved = true
                } else {
                    capture.receipt.outcomeUnknown = true
                    Toast.makeText(this, e.message, Toast.LENGTH_LONG).show()
                    // Drop only this consumed in-memory capture; never replay an unknown commit.
                    return false
                }
                true
            } catch (_: Exception) {
                false
            }
            if (saved) {
                Toast.makeText(this@OfflineVaultApp, "已将账号保存到密码库", Toast.LENGTH_SHORT).show()
            } else {
                // Requeue once, then stop so a persistent failure cannot spin or block the UI.
                retainPendingAutofillSave(capture)
                return false
            }
        }
        return false
    }

    private fun retainPendingAutofillSave(capture: PendingAutofillSave.Capture) {
        if (!PendingAutofillSave.retry(capture)) {
            Toast.makeText(this, "账号暂存失败，请重新触发自动填充保存", Toast.LENGTH_LONG).show()
        }
    }
}
