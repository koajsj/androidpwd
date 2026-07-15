package com.offlinevault.utils

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import java.util.UUID

/**
 * Copies sensitive values to the clipboard and automatically wipes them after a delay so a copied
 * password does not linger. On Android 13+ the clip is also flagged as sensitive so it is hidden
 * from the clipboard preview.
 */
object ClipboardHelper {

    private const val DEFAULT_SENSITIVE_CLEAR_SECONDS = 10
    private const val CLIP_MARKER_KEY = "com.offlinevault.clip_marker"

    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null

    fun copySensitive(context: Context, label: String, value: String, clearAfterSeconds: Int) {
        val effectiveClearSeconds =
            if (clearAfterSeconds > 0) clearAfterSeconds else DEFAULT_SENSITIVE_CLEAR_SECONDS
        val appContext = context.applicationContext
        val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(label, value)
        // Do not retain [value] in the delayed Runnable. A random, non-sensitive marker lets us
        // identify this exact clip later without keeping a copied password alive in app memory.
        val marker = UUID.randomUUID().toString()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
                putString(CLIP_MARKER_KEY, marker)
            }
        }
        runCatching { clipboard.setPrimaryClip(clip) }.getOrElse { return }

        pendingClear?.let { handler.removeCallbacks(it) }
        pendingClear = null
        val runnable = Runnable { clear(appContext, marker) }
        pendingClear = runnable
        handler.postDelayed(runnable, effectiveClearSeconds * 1000L)
    }

    fun copyPlain(context: Context, label: String, value: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        runCatching { clipboard.setPrimaryClip(ClipData.newPlainText(label, value)) }
    }

    /**
     * Clears the copied secret when the timer fires. Android can block clipboard reads while an app
     * is backgrounded; in that case we still clear fail-closed. Otherwise we clear only when the
     * non-sensitive marker proves this is still the clip created by [copySensitive].
     */
    private fun clear(context: Context, expectedMarker: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val description = runCatching { clipboard.primaryClipDescription }.getOrNull()
        val currentMarker = description?.extras?.getString(CLIP_MARKER_KEY)
        if (description == null || currentMarker == expectedMarker) {
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    clipboard.clearPrimaryClip()
                } else {
                    clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            }
        }
        pendingClear = null
    }
}
