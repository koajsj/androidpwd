package com.offlinevault.viewmodel

import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelProvider.AndroidViewModelFactory.Companion.APPLICATION_KEY
import androidx.lifecycle.viewmodel.CreationExtras
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.offlinevault.OfflineVaultApp

/** Builds every feature ViewModel from the app's [com.offlinevault.AppContainer]. */
object ViewModelFactory {

    val Factory: ViewModelProvider.Factory = viewModelFactory {

        initializer {
            AuthViewModel(
                app().container.keyManager,
                app().container.securityPreferences,
                app().container.riskEngine
            )
        }
        initializer {
            PasswordListViewModel(
                app().container.passwordRepository,
                app().container.vaultRepository,
                app().container.backupManager,
                app().container.securityPreferences
            )
        }
        initializer {
            PasswordEditViewModel(app().container.passwordRepository, app().container.vaultRepository)
        }
        initializer {
            PasswordDetailViewModel(app().container.passwordRepository)
        }
        initializer {
            TrashViewModel(app().container.passwordRepository)
        }
        initializer {
            PasswordHealthViewModel(app().container.passwordRepository, app().container.securityPreferences)
        }
        initializer {
            SettingsViewModel(
                app().container.keyManager,
                app().container.securityPreferences,
                app().container.backupManager,
                app().container.vaultRepository
            )
        }
    }

    private fun CreationExtras.app(): OfflineVaultApp =
        this[APPLICATION_KEY] as OfflineVaultApp
}
