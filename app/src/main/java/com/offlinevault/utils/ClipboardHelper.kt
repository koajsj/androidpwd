package com.offlinevault.utils

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import java.util.UUID

/**
 * Copies sensitive values to the clipboard and automatically wipes them after a delay so a copied
 * password does not linger. On Android 13+ the clip is also flagged as sensitive so it is hidden
 * from the clipboard preview.
 */
object ClipboardHelper {

    private const val DEFAULT_SENSITIVE_CLEAR_SECONDS = 10
    private const val CLIP_MARKER_KEY = "com.offlinevault.clip_marker"
    internal const val CLEAR_ALARM_ACTION = "com.offlinevault.action.CLEAR_SENSITIVE_CLIP"
    internal const val CLEAR_ALARM_MARKER = "clip_marker"
    private const val CLEAR_ALARM_REQUEST_CODE = 7_021
    private const val CLEAR_STATE_PREFS = "offline_vault_clipboard_state"
    private const val CLEAR_STATE_MARKER = "marker"
    private const val CLEAR_STATE_EXPIRES_AT = "expires_at"

    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null
    private var pendingMarker: String? = null

    fun copySensitive(context: Context, label: String, value: String, clearAfterSeconds: Int): Boolean {
        val effectiveClearSeconds =
            if (clearAfterSeconds > 0) clearAfterSeconds else DEFAULT_SENSITIVE_CLEAR_SECONDS
        val appContext = context.applicationContext
        val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return false
        val clip = ClipData.newPlainText(label, value)
        // Do not retain [value] in the delayed Runnable. A random, non-sensitive marker lets us
        // identify this exact clip later without keeping a copied password alive in app memory.
        val marker = UUID.randomUUID().toString()
        // minSdk is Android 8.0 (API 26), so ClipDescription extras are always available.
        clip.description.extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
            putString(CLIP_MARKER_KEY, marker)
        }
        runCatching { clipboard.setPrimaryClip(clip) }.getOrElse { return false }

        pendingClear?.let { handler.removeCallbacks(it) }
        cancelScheduledClear(appContext)
        pendingMarker = marker
        val delayMs = effectiveClearSeconds * 1000L
        savePendingState(appContext, marker, System.currentTimeMillis() + delayMs)
        val runnable = Runnable { clear(appContext, marker) }
        pendingClear = runnable
        handler.postDelayed(runnable, delayMs)
        // Handler covers the normal foreground case. The inexact alarm keeps the best-effort
        // cleanup alive if Android reclaims this process before the delay expires. No exact-alarm
        // permission is requested; the OS may defer this fallback while idle.
        scheduleSystemClear(appContext, marker, delayMs)
        return true
    }

    fun copyPlain(context: Context, label: String, value: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        runCatching { clipboard.setPrimaryClip(ClipData.newPlainText(label, value)) }.onSuccess {
            // The sensitive clip has already been replaced, so a later timeout must not retain a
            // redundant alarm or state record.
            discardPendingClear(context.applicationContext)
        }
    }

    /** Clears the app-owned sensitive clip immediately when the vault locks. */
    fun clearPendingSensitive(context: Context) {
        val appContext = context.applicationContext
        val marker = pendingMarker ?: storedMarker(appContext) ?: return
        clear(appContext, marker)
    }

    /** Restores a pending expiry after a process restart, without persisting any clipboard value. */
    fun restorePendingSensitiveClear(context: Context) {
        val appContext = context.applicationContext
        val marker = storedMarker(appContext) ?: return
        val remainingMs = storedExpiry(appContext) - System.currentTimeMillis()
        if (remainingMs <= 0) {
            clear(appContext, marker)
            return
        }
        pendingClear?.let { handler.removeCallbacks(it) }
        pendingMarker = marker
        val runnable = Runnable { clear(appContext, marker) }
        pendingClear = runnable
        handler.postDelayed(runnable, remainingMs)
        scheduleSystemClear(appContext, marker, remainingMs)
    }

    /** Invoked only by the app-private alarm receiver. */
    internal fun clearScheduledSensitive(context: Context, marker: String?) {
        if (!marker.isNullOrBlank()) clear(context.applicationContext, marker)
    }

    /**
     * Clears the copied secret when the timer fires, but only when its non-sensitive marker still
     * proves this is the clip created by [copySensitive]. Android can block clipboard reads while
     * an app is backgrounded; treating that as a match could erase text the user copied later in
     * another app, so it is a best-effort cleanup in that case.
     */
    private fun clear(context: Context, expectedMarker: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val description = clipboard?.let {
            runCatching { it.primaryClipDescription }.getOrNull()
        }
        if (clipboard == null || description == null) {
            // Clipboard reads are restricted for background apps on recent Android versions.
            // Keep the non-sensitive marker and retry instead of declaring success while the
            // password may still be present.
            deferClearUntilForeground(context, expectedMarker)
            return
        }

        val currentMarker = description.extras?.getString(CLIP_MARKER_KEY)
        if (currentMarker == expectedMarker) {
            val cleared = runCatching {
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                        clipboard.clearPrimaryClip()
                    } else {
                        clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                    }
                }.isSuccess
            if (!cleared) {
                deferClearUntilForeground(context, expectedMarker)
                return
            }
        }
        // A different marker proves the user replaced the clip, so the old cleanup can be
        // discarded without erasing unrelated clipboard content.
        discardPendingClear(context, expectedMarker)
    }

    private fun deferClearUntilForeground(context: Context, expectedMarker: String) {
        if (storedMarker(context) != expectedMarker && pendingMarker != expectedMarker) return
        pendingClear?.let { handler.removeCallbacks(it) }
        pendingMarker = expectedMarker
        pendingClear = null
        // A BroadcastReceiver is not a foreground clipboard reader either, so repeated alarms
        // cannot make progress and only waste battery. Keep the persisted marker; the visible
        // activities call restorePendingSensitiveClear() from onStart and retry immediately.
        cancelScheduledClear(context)
    }

    private fun discardPendingClear(context: Context, expectedMarker: String) {
        if (pendingMarker == expectedMarker) {
            pendingClear?.let { handler.removeCallbacks(it) }
            pendingMarker = null
            pendingClear = null
        }
        if (storedMarker(context) == expectedMarker) {
            clearPendingState(context)
            cancelScheduledClear(context)
        }
    }

    private fun discardPendingClear(context: Context) {
        pendingClear?.let { handler.removeCallbacks(it) }
        pendingClear = null
        pendingMarker = null
        clearPendingState(context)
        cancelScheduledClear(context)
    }

    private fun scheduleSystemClear(context: Context, marker: String, delayMs: Long) {
        val alarmManager = context.getSystemService(AlarmManager::class.java) ?: return
        val triggerAt = SystemClock.elapsedRealtime() + delayMs
        runCatching {
            alarmManager.setAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                triggerAt,
                clearPendingIntent(context, marker)
            )
        }
    }

    private fun cancelScheduledClear(context: Context) {
        val alarmManager = context.getSystemService(AlarmManager::class.java) ?: return
        runCatching { alarmManager.cancel(clearPendingIntent(context, "")) }
    }

    private fun clearPendingIntent(context: Context, marker: String): PendingIntent =
        PendingIntent.getBroadcast(
            context,
            CLEAR_ALARM_REQUEST_CODE,
            Intent(context, ClipboardClearReceiver::class.java)
                .setAction(CLEAR_ALARM_ACTION)
                .putExtra(CLEAR_ALARM_MARKER, marker),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

    private fun state(context: Context) =
        context.getSharedPreferences(CLEAR_STATE_PREFS, Context.MODE_PRIVATE)

    private fun savePendingState(context: Context, marker: String, expiresAt: Long) {
        state(context).edit()
            .putString(CLEAR_STATE_MARKER, marker)
            .putLong(CLEAR_STATE_EXPIRES_AT, expiresAt)
            .apply()
    }

    private fun clearPendingState(context: Context) {
        state(context).edit().clear().apply()
    }

    private fun storedMarker(context: Context): String? =
        state(context).getString(CLEAR_STATE_MARKER, null)

    private fun storedExpiry(context: Context): Long =
        state(context).getLong(CLEAR_STATE_EXPIRES_AT, 0L)
}
