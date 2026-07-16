package com.offlinevault.utils

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** App-private, best-effort fallback for sensitive clipboard cleanup after process reclamation. */
class ClipboardClearReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ClipboardHelper.CLEAR_ALARM_ACTION) return
        ClipboardHelper.clearScheduledSensitive(
            context,
            intent.getStringExtra(ClipboardHelper.CLEAR_ALARM_MARKER)
        )
    }
}
