package com.offlinevault

import android.content.Context
import com.offlinevault.data.backup.BackupManager
import com.offlinevault.data.db.AppDatabase
import com.offlinevault.data.db.VaultIntegrityChecker
import com.offlinevault.data.preferences.SecurityPreferences
import com.offlinevault.data.repository.PasswordRepository
import com.offlinevault.data.repository.VaultRepository
import com.offlinevault.security.KeyManager
import com.offlinevault.security.MnemonicManager

/** Tiny manual dependency container. Keeps the app free of any DI framework. */
class AppContainer(context: Context) {

    private val database = AppDatabase.get(context)
    private val mnemonicManager = MnemonicManager()

    val securityPreferences = SecurityPreferences(context.applicationContext)
    val keyManager = KeyManager(securityPreferences, mnemonicManager)
    val integrityChecker = VaultIntegrityChecker(database)

    val vaultRepository = VaultRepository(database.vaultDao())
    val passwordRepository = PasswordRepository(database.passwordDao())
    val backupManager = BackupManager(vaultRepository, passwordRepository)
}
