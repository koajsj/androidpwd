package com.offlinevault.ui.components

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.Window
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalContext
import com.offlinevault.security.SecureWindowPolicy
import java.util.WeakHashMap

private val windowPolicies = WeakHashMap<Window, SecureWindowPolicy>()

/** Called on Main, including when DataStore re-emits the preference after a lifecycle restart. */
fun setScreenshotProtection(window: Window, blocked: Boolean) {
    val policy = windowPolicies.getOrPut(window) { SecureWindowPolicy() }
    policy.screenshotBlocked = blocked
    window.applyProtection(policy)
}

private fun Window.applyProtection(policy: SecureWindowPolicy) {
    if (policy.isSecure) addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    else clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
}

@Composable
fun SecureWindowEffect(enabled: Boolean) {
    val context = LocalContext.current
    DisposableEffect(context, enabled) {
        val window = context.findActivity()?.window
        val policy = if (enabled && window != null) {
            windowPolicies.getOrPut(window) { SecureWindowPolicy() }.also {
                it.acquire()
                window.applyProtection(it)
            }
        } else {
            null
        }
        onDispose {
            if (policy != null && window != null) {
                policy.release()
                window.applyProtection(policy)
            }
        }
    }
}

private fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
