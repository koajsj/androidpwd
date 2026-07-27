package com.offlinevault

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.compose.animation.AnimatedContentTransitionScope.SlideDirection
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.LocalContext
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.offlinevault.security.LockGuard
import com.offlinevault.security.SessionManager
import com.offlinevault.ui.screens.PasswordDetailScreen
import com.offlinevault.ui.screens.PasswordEditScreen
import com.offlinevault.ui.screens.PasswordHealthScreen
import com.offlinevault.ui.screens.PasswordListScreen
import com.offlinevault.ui.screens.RecoverScreen
import com.offlinevault.ui.screens.SettingsScreen
import com.offlinevault.ui.screens.SetupScreen
import com.offlinevault.ui.screens.TrashScreen
import com.offlinevault.ui.screens.UnlockScreen
import com.offlinevault.ui.theme.OfflineVaultTheme
import com.offlinevault.ui.theme.VaultBackground
import com.offlinevault.ui.theme.VaultBackgroundElevated
import com.offlinevault.utils.BiometricHelper
import com.offlinevault.utils.ClipboardHelper
import com.offlinevault.viewmodel.AppLockState
import com.offlinevault.viewmodel.AuthViewModel
import com.offlinevault.viewmodel.PasswordDetailViewModel
import com.offlinevault.viewmodel.PasswordEditViewModel
import com.offlinevault.viewmodel.PasswordHealthViewModel
import com.offlinevault.viewmodel.PasswordListViewModel
import com.offlinevault.viewmodel.SettingsViewModel
import com.offlinevault.viewmodel.TrashViewModel
import com.offlinevault.viewmodel.ViewModelFactory
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : FragmentActivity() {

    private val prefs by lazy { (application as OfflineVaultApp).container.securityPreferences }
    private var backgroundedAt: Long = 0L
    private var autoLockJob: Job? = null

    @Volatile
    private var lockOnScreenOff = false

    // Keep the timeout available synchronously on the lifecycle callback. Activity Result
    // callbacks can run before a coroutine launched from onStart, so checking DataStore there
    // left a short window in which an expired export/import action could still run.
    @Volatile
    private var autoLockSeconds = 0

    // Locks the vault the instant the device screen turns off, when the user enabled that option.
    private val screenOffReceiver = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: android.content.Context?, intent: android.content.Intent?) {
            if (intent?.action == android.content.Intent.ACTION_SCREEN_OFF &&
                lockOnScreenOff && SessionManager.isUnlocked
            ) {
                SessionManager.lock()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)

        // Explicit NOT_EXPORTED flag: required for context-registered receivers on Android 14+
        // (the system still delivers this protected broadcast; only other apps are excluded).
        androidx.core.content.ContextCompat.registerReceiver(
            this,
            screenOffReceiver,
            android.content.IntentFilter(android.content.Intent.ACTION_SCREEN_OFF),
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
        )
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                prefs.lockOnScreenOffFlow.collect { lockOnScreenOff = it }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                prefs.autoLockSecondsFlow.collect { autoLockSeconds = it }
            }
        }

        // Privacy hardening: exclude the whole app from the autofill framework so no third-party
        // autofill service or keyboard can capture the master password / stored credentials typed
        // here. (Our own autofill service only reads OTHER apps, so this does not affect it.)
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

        // Dark UI: keep system-bar icons light and readable over the transparent bars.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)
        )

        // Apply / clear FLAG_SECURE reactively from the screenshot-block setting.
        // Start fail-closed: DataStore is asynchronous, so a recreated unlocked activity must not
        // draw sensitive content before the persisted preference is available.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                try {
                    prefs.screenshotBlockedFlow.collect { blocked ->
                        if (blocked) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            }
        }

        setContent {
            OfflineVaultTheme {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.verticalGradient(
                                listOf(VaultBackgroundElevated, VaultBackground)
                            )
                        )
                ) {
                    AppRoot()
                }
            }
        }
    }

    override fun onDestroy() {
        // Rotation recreates the activity but not the process. Keeping the in-memory key across
        // that short configuration handoff avoids an unnecessary re-login while FLAG_SECURE stays
        // applied; actual finishing/destruction still locks immediately.
        if (!isChangingConfigurations) {
            SessionManager.lock()
        }
        runCatching { unregisterReceiver(screenOffReceiver) }
        super.onDestroy()
    }

    override fun onStop() {
        super.onStop()
        // A configuration recreation is not backgrounding. Do not make a portrait/landscape
        // change behave like leaving the app, especially when auto-lock is set to immediate.
        if (isChangingConfigurations) {
            backgroundedAt = 0L
            return
        }
        // Record every transition, including system UI. A picker must not bypass the configured
        // timeout simply because it temporarily fronted the activity.
        backgroundedAt = System.currentTimeMillis()
        // Only the locked-screen biometric prompt may defer the timer while its CryptoObject is
        // in flight. File pickers/settings must still clear the in-memory DEK when the configured
        // timeout expires, even if the user has not returned to this activity yet.
        if (LockGuard.suppressNextBackground && LockGuard.suppressAutoLockOnReturn) return
        scheduleAutoLock()
    }

    override fun onStart() {
        super.onStart()
        autoLockJob?.cancel()
        autoLockJob = null
        // Android may block clipboard reads while the app is backgrounded. Retry any expired
        // app-owned sensitive clip now that the activity is visible again.
        ClipboardHelper.restorePendingSensitiveClear(applicationContext)
        if (LockGuard.suppressNextBackground) {
            val deferForBiometricPrompt = LockGuard.suppressAutoLockOnReturn
            LockGuard.suppressNextBackground = false
            LockGuard.suppressAutoLockOnReturn = false
            // BiometricPrompt callbacks clear their guard as soon as they resolve. On OEMs where
            // the prompt briefly stops the host activity, do not discard its CryptoObject mid-flow.
            if (deferForBiometricPrompt) return
        }
        // A document picker or system-settings page is not an authentication prompt. It must not
        // grant an extra unlocked interval: honour the configured immediate/timeout auto-lock as
        // soon as the user returns, before handling its Activity Result.
        if (!SessionManager.isUnlocked || backgroundedAt == 0L) return
        val seconds = autoLockSeconds
        if (seconds == 0) {
            // External picker/biometric flows are allowed to finish, but once control returns to
            // the vault the immediate-lock setting must take effect before its result callback.
            SessionManager.lock()
        } else {
            val elapsed = System.currentTimeMillis() - backgroundedAt
            if (elapsed >= seconds * 1000L) SessionManager.lock()
        }
    }

    private fun scheduleAutoLock() {
        autoLockJob?.cancel()
        val seconds = autoLockSeconds
        if (seconds <= 0) {
            SessionManager.lock()
            return
        }
        autoLockJob = lifecycleScope.launch {
            delay(seconds * 1000L)
            SessionManager.lock()
        }
    }
}

@Composable
private fun AppRoot() {
    val activity = LocalContext.current as FragmentActivity
    val authVm: AuthViewModel = viewModel(factory = ViewModelFactory.Factory)
    val settingsVm: SettingsViewModel = viewModel(factory = ViewModelFactory.Factory)

    val lockState by authVm.lockState.collectAsStateWithLifecycle()
    val unlockState by authVm.unlockState.collectAsStateWithLifecycle()
    val biometricEnabled by authVm.biometricEnabled.collectAsStateWithLifecycle()
    val recoveryQuestion by authVm.recoveryQuestion.collectAsStateWithLifecycle()
    val mnemonicEnabled by authVm.mnemonicEnabled.collectAsStateWithLifecycle()
    val credentialType by authVm.credentialType.collectAsStateWithLifecycle()
    val setupInProgress by authVm.setupInProgress.collectAsStateWithLifecycle()
    val clipboardSeconds by settingsVm.clipboardClearSeconds.collectAsStateWithLifecycle()

    // A copied password should not outlive an unlocked session, even if the user selected a
    // longer clipboard timeout. ClipboardHelper only clears clips it marked as app-owned.
    LaunchedEffect(lockState) {
        if (lockState == AppLockState.LOCKED) {
            ClipboardHelper.clearPendingSensitive(activity.applicationContext)
        }
    }

    val biometricAvailable = remember { BiometricHelper.canAuthenticate(activity) }

    var showRecover by remember { mutableStateOf(false) }
    var pendingEnableBiometric by remember { mutableStateOf(false) }

    fun triggerBiometricUnlock() {
        authVm.prepareBiometricCipher { cipher ->
            if (cipher != null) {
                LockGuard.suppressNextBackground = true
                LockGuard.suppressAutoLockOnReturn = true
                BiometricHelper.authenticate(
                    activity = activity,
                    title = "解锁离线密码库",
                    subtitle = "使用指纹解锁",
                    cipher = cipher,
                    // Clear the suppression as soon as the prompt resolves so a later real
                    // backgrounding is not wrongly skipped (the prompt often causes no onStop).
                    onSuccess = {
                        LockGuard.suppressNextBackground = false
                        LockGuard.suppressAutoLockOnReturn = false
                        authVm.finishBiometricUnlock(it)
                    },
                    onError = {
                        LockGuard.suppressNextBackground = false
                        LockGuard.suppressAutoLockOnReturn = false
                    },
                    onCancel = {
                        LockGuard.suppressNextBackground = false
                        LockGuard.suppressAutoLockOnReturn = false
                    }
                )
            }
        }
    }

    fun enableBiometric(onDone: (Boolean) -> Unit) {
        settingsVm.prepareEnableBiometricCipher { cipher ->
            if (cipher == null) { onDone(false); return@prepareEnableBiometricCipher }
            // Enabling biometrics happens from an already unlocked settings screen. It must obey
            // the normal background auto-lock policy; only the locked-screen authentication flow
            // may defer a lifecycle check while its CryptoObject is in flight.
            BiometricHelper.authenticate(
                activity = activity,
                title = "启用指纹解锁",
                subtitle = "验证后启用指纹解锁",
                cipher = cipher,
                onSuccess = {
                    settingsVm.finishEnableBiometric(it, onDone)
                },
                onError = { onDone(false) },
                onCancel = { onDone(false) }
            )
        }
    }

    // Enable biometric immediately after first-time setup if the user opted in.
    LaunchedEffect(lockState, pendingEnableBiometric) {
        if (lockState == AppLockState.UNLOCKED && pendingEnableBiometric) {
            pendingEnableBiometric = false
            enableBiometric { }
        }
    }

    // Never animate away from decrypted content when the session locks. A crossfade keeps the
    // previous composition alive for a few frames, which is pleasant for ordinary navigation but
    // the wrong trade-off at an authentication boundary.
    when (lockState) {
            AppLockState.LOADING -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            }

            AppLockState.SETUP -> SetupScreen(
                setupError = authVm.setupError.collectAsStateWithLifecycle().value,
                setupInProgress = setupInProgress,
                biometricAvailable = biometricAvailable,
                onCreate = { master, question, answer, mnemonicPhrase, enableBio, credType ->
                    pendingEnableBiometric = enableBio
                    authVm.setup(master, question, answer, credType, mnemonicPhrase)
                }
            )

            AppLockState.LOCKED -> {
                if (showRecover) {
                    RecoverScreen(
                        question = recoveryQuestion,
                        credentialType = credentialType,
                        mnemonicEnabled = mnemonicEnabled,
                        onRecoverByAnswer = { answer, newPassword, onResult ->
                            authVm.recover(answer, newPassword) { ok, msg ->
                                onResult(ok, msg)
                            }
                        },
                        onRecoverByMnemonic = { mnemonic, newPassword, onResult ->
                            authVm.recoverWithMnemonic(mnemonic, newPassword) { ok, msg ->
                                onResult(ok, msg)
                            }
                        },
                        onBack = { showRecover = false }
                    )
                } else {
                    UnlockScreen(
                        state = unlockState,
                        biometricEnabled = biometricEnabled,
                        credentialType = credentialType,
                        onUnlock = { authVm.unlockWithPassword(it) },
                        onBiometric = { triggerBiometricUnlock() },
                        onForgot = { showRecover = true }
                    )
                }
            }

            AppLockState.UNLOCKED -> MainNavHost(
                clipboardSeconds = clipboardSeconds,
                biometricAvailable = biometricAvailable,
                settingsViewModel = settingsVm,
                onEnableBiometric = { onDone -> enableBiometric(onDone) }
            )
    }
}

@Composable
private fun MainNavHost(
    clipboardSeconds: Int,
    biometricAvailable: Boolean,
    settingsViewModel: SettingsViewModel,
    onEnableBiometric: (onDone: (Boolean) -> Unit) -> Unit
) {
    val navController = rememberNavController()

    NavHost(
        navController = navController,
        startDestination = "passwords",
        enterTransition = { fadeIn(tween(250)) + slideIntoContainer(SlideDirection.Start, tween(250)) },
        exitTransition = { fadeOut(tween(200)) + slideOutOfContainer(SlideDirection.Start, tween(200)) },
        popEnterTransition = { fadeIn(tween(250)) + slideIntoContainer(SlideDirection.End, tween(250)) },
        popExitTransition = { fadeOut(tween(200)) + slideOutOfContainer(SlideDirection.End, tween(200)) }
    ) {
        composable("passwords") {
            val vm: PasswordListViewModel = viewModel(factory = ViewModelFactory.Factory)
            LaunchedEffect(Unit) { vm.jiazaiMoren() }
            PasswordListScreen(
                viewModel = vm,
                onOpenItem = { navController.navigate("detail/$it") },
                onAddItem = {
                    val vaultId = vm.dangqianMimakuId()
                    if (vaultId.isNotEmpty()) navController.navigate("add/$vaultId")
                },
                onOpenSettings = { navController.navigate("settings") }
            )
        }

        composable("detail/{passwordId}") { entry ->
            val passwordId = entry.arguments?.getString("passwordId").orEmpty()
            val vm: PasswordDetailViewModel = viewModel(factory = ViewModelFactory.Factory)
            PasswordDetailScreen(
                viewModel = vm,
                passwordId = passwordId,
                clipboardSeconds = clipboardSeconds,
                onBack = { navController.popBackStack() },
                onEdit = { navController.navigate("edit/$passwordId") }
            )
        }

        composable("add/{vaultId}") { entry ->
            val vaultId = entry.arguments?.getString("vaultId").orEmpty()
            val vm: PasswordEditViewModel = viewModel(factory = ViewModelFactory.Factory)
            PasswordEditScreen(
                viewModel = vm,
                vaultId = vaultId,
                passwordId = null,
                onDone = { navController.popBackStack() },
                onBack = { navController.popBackStack() }
            )
        }

        composable("edit/{passwordId}") { entry ->
            val passwordId = entry.arguments?.getString("passwordId").orEmpty()
            val vm: PasswordEditViewModel = viewModel(factory = ViewModelFactory.Factory)
            PasswordEditScreen(
                viewModel = vm,
                vaultId = "",
                passwordId = passwordId,
                onDone = { navController.popBackStack() },
                onBack = { navController.popBackStack() }
            )
        }

        composable("settings") {
            SettingsScreen(
                viewModel = settingsViewModel,
                biometricAvailable = biometricAvailable,
                onBack = { navController.popBackStack() },
                onEnableBiometric = onEnableBiometric,
                onOpenTrash = { navController.navigate("trash") },
                onOpenHealth = { navController.navigate("health") }
            )
        }

        composable("trash") {
            val vm: TrashViewModel = viewModel(factory = ViewModelFactory.Factory)
            TrashScreen(viewModel = vm, onBack = { navController.popBackStack() })
        }

        composable("health") {
            val vm: PasswordHealthViewModel = viewModel(factory = ViewModelFactory.Factory)
            PasswordHealthScreen(
                viewModel = vm,
                onBack = { navController.popBackStack() },
                onOpenItem = { navController.navigate("detail/$it") }
            )
        }
    }
}
