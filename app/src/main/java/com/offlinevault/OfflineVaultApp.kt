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
                withContext(Dispatchers.IO) {
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
