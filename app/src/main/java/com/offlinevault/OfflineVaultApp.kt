package com.offlinevault

import android.app.Application
import android.widget.Toast
import com.offlinevault.autofill.PendingAutofillSave
import com.offlinevault.security.SessionManager
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
        applicationScope.launch {
            SessionManager.unlocked.filter { it }.collect {
                val integrityOk = withContext(Dispatchers.IO) {
                    try {
                        container.passwordRepository.assertVaultIntegrity()
                        container.vaultRepository.migrateLegacyMetadata()
                        container.passwordRepository.migrateLegacyMetadata()
                        // Permanently remove recycle-bin items past their retention window.
                        container.passwordRepository.purgeExpiredTrash()
                        true
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        false
                    }
                }
                if (!integrityOk) {
                    SessionManager.lock()
                    Toast.makeText(this@OfflineVaultApp, "密码库完整性校验失败，已锁定", Toast.LENGTH_SHORT).show()
                    return@collect
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
            PendingAutofillSave.set(capture)
        }
    }
}
