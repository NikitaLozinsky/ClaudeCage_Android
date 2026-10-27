package com.example.claudecageand.notifications

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.example.claudecageand.MainActivity
import com.example.claudecageand.R
import com.example.claudecageand.telemetry.SecurityAuditLogger
import com.example.claudecageand.ui.AppIconManager
import com.example.claudecageand.ui.AppIconOption
import java.util.Locale

/**
 * W3C Web Notification API Bridge for Claude in Chromium WebView.
 *
 * Provides a secure, zero-leak bridge between web JavaScript (window.Notification)
 * and the Android system NotificationManager.
 */
class ClaudeCageNotificationBridge(
    private val activity: Activity,
    private val getActiveUrl: () -> String?,
    private val webViewProvider: () -> WebView?,
    private val onRequestPermission: (reqId: String) -> Unit,
    private val auditLogger: SecurityAuditLogger,
    private val appIconManager: AppIconManager? = null
) {
    companion object {
        const val TAG = "ClaudeCageNotif"
        const val CHANNEL_ID = "claude_cage_notifications"
        const val EXTRA_NOTIFICATION_ID = "extra_claude_notification_id"

        val ALLOWED_NOTIFICATION_ORIGINS = setOf(
            "https://claude.ai",
            "https://anthropic.com",
            "https://claude.com"
        )

        fun isOriginPermitted(url: String?): Boolean {
            if (url.isNullOrBlank()) return false
            val lower = url.trim().lowercase(Locale.ROOT)
            return ALLOWED_NOTIFICATION_ORIGINS.any { allowed ->
                lower == allowed || lower.startsWith("$allowed/") || lower.startsWith("$allowed:")
            }
        }
    }

    fun hasNotificationPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                activity,
                android.Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED &&
            NotificationManagerCompat.from(activity).areNotificationsEnabled()
        } else {
            NotificationManagerCompat.from(activity).areNotificationsEnabled()
        }
    }

    @JavascriptInterface
    fun getPermissionStatus(): String {
        val url = getActiveUrl()
        if (!isOriginPermitted(url)) return "denied"
        return if (hasNotificationPermission()) "granted" else "default"
    }

    @JavascriptInterface
    fun requestPermission(reqId: String) {
        val url = getActiveUrl()
        if (!isOriginPermitted(url)) {
            resolveJsPermission(reqId, "denied")
            return
        }
        activity.runOnUiThread {
            val verifiedUrl = getActiveUrl() ?: webViewProvider()?.url
            if (!isOriginPermitted(verifiedUrl)) {
                auditLogger.logWarning("Notification", "Blocked permission request from unauthorized origin on UI thread: $verifiedUrl")
                resolveJsPermission(reqId, "denied")
                return@runOnUiThread
            }
            if (hasNotificationPermission()) {
                resolveJsPermission(reqId, "granted")
            } else {
                onRequestPermission(reqId)
            }
        }
    }

    @JavascriptInterface
    fun showNotification(
        notifId: Int,
        title: String,
        body: String,
        tag: String?,
        iconUrl: String?,
        silent: Boolean
    ) {
        val url = getActiveUrl()
        if (!isOriginPermitted(url)) {
            auditLogger.logWarning("Notification", "Blocked notification from unauthorized origin: $url")
            return
        }

        activity.runOnUiThread {
            val verifiedUrl = getActiveUrl() ?: webViewProvider()?.url
            if (!isOriginPermitted(verifiedUrl)) {
                auditLogger.logWarning("Notification", "Blocked notification from unauthorized origin on UI thread: $verifiedUrl")
                return@runOnUiThread
            }

            if (!hasNotificationPermission()) {
                auditLogger.logWarning("Notification", "Cannot display notification $notifId: permission not granted")
                return@runOnUiThread
            }

            try {
                ensureNotificationChannel(activity)

                val cleanTitle = title.trim().take(128).ifBlank { "Claude" }
                val cleanBody = body.trim().take(2048)
                val cleanTag = tag?.trim()?.take(64)

                val intent = Intent(activity, MainActivity::class.java).apply {
                    action = Intent.ACTION_MAIN
                    addCategory(Intent.CATEGORY_LAUNCHER)
                    flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                    putExtra(EXTRA_NOTIFICATION_ID, notifId.toString())
                }

                val pendingIntent = PendingIntent.getActivity(
                    activity,
                    notifId,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )

                val iconRes = if (appIconManager?.getCurrentIcon() == AppIconOption.VARIANT_2) {
                    R.mipmap.ic_launcher_opt2
                } else {
                    R.mipmap.ic_launcher_opt1
                }

                val builder = NotificationCompat.Builder(activity, CHANNEL_ID)
                    .setSmallIcon(iconRes)
                    .setContentTitle(cleanTitle)
                    .setContentText(cleanBody)
                    .setStyle(NotificationCompat.BigTextStyle().bigText(cleanBody))
                    .setPriority(if (silent) NotificationCompat.PRIORITY_LOW else NotificationCompat.PRIORITY_HIGH)
                    .setAutoCancel(true)
                    .setContentIntent(pendingIntent)

                if (!silent) {
                    builder.setDefaults(NotificationCompat.DEFAULT_ALL)
                }

                val nm = NotificationManagerCompat.from(activity)
                if (cleanTag.isNullOrBlank()) {
                    nm.notify(notifId, builder.build())
                } else {
                    nm.notify(cleanTag, notifId, builder.build())
                }

                auditLogger.logInfo("Notification", "Notification displayed: id=$notifId title='$cleanTitle' tag=$cleanTag")
                (activity as? MainActivity)?.releaseBackgroundWakeLock()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to display notification", e)
                auditLogger.logWarning("Notification", "Failed to display notification $notifId: ${e.message}")
            }
        }
    }

    @JavascriptInterface
    fun cancelNotification(tag: String?, notifId: Int) {
        val url = getActiveUrl()
        if (!isOriginPermitted(url)) return
        activity.runOnUiThread {
            try {
                val nm = NotificationManagerCompat.from(activity)
                val cleanTag = tag?.trim()
                if (cleanTag.isNullOrBlank()) {
                    nm.cancel(notifId)
                } else {
                    nm.cancel(cleanTag, notifId)
                }
                auditLogger.logInfo("Notification", "Notification cancelled: id=$notifId tag=$cleanTag")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to cancel notification", e)
            }
        }
    }

    fun resolveJsPermission(reqId: String, status: String) {
        activity.runOnUiThread {
            val safeReqId = reqId.replace("\\", "\\\\").replace("'", "\\'")
            val safeStatus = status.replace("\\", "\\\\").replace("'", "\\'")
            val js = "window._pendingPermRequests?.['$safeReqId']?.('$safeStatus'); delete window._pendingPermRequests?.['$safeReqId'];"
            webViewProvider()?.evaluateJavascript(js, null)
        }
    }

    fun ensureNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(NotificationManager::class.java) ?: return
            val existing = nm.getNotificationChannel(CHANNEL_ID)
            if (existing == null) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    "Claude Notifications",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Notifications for Claude responses and completed messages"
                    enableLights(true)
                    enableVibration(true)
                    setShowBadge(true)
                    lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                }
                nm.createNotificationChannel(channel)
            }
        }
    }
}
