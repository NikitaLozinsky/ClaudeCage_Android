package com.example.claudecageand

import android.app.Application
import android.content.Context
import android.os.Build
import android.system.Os
import android.util.Log
import com.example.claudecageand.accounts.AccountProfileManager
import com.example.claudecageand.net.VpnGatekeeperProxy
import com.example.claudecageand.net.VpnStateMonitor
import com.example.claudecageand.telemetry.SecurityAuditLogger
import com.example.claudecageand.ui.AppIconManager
import com.example.claudecageand.ui.UiLanguageManager
import java.util.Locale
import java.util.TimeZone

/**
 * Custom [Application] class enforcing process-level timezone, locale, and environment spoofing
 * BEFORE any Chromium / WebView shared library is initialized in the process.
 *
 * CRITICAL ANTI-FINGERPRINTING & LIFECYCLE GUARANTEES:
 * 1. Sets POSIX 'TZ' environment variable to "Europe/Amsterdam" via [Os.setenv].
 * 2. Overrides default JVM [TimeZone] to "Europe/Amsterdam" (CET/CEST).
 * 3. Overrides default JVM [Locale] and configuration to [Locale.US] ("en-US").
 * 4. Initializes and retains process-global singletons ([VpnStateMonitor], [VpnGatekeeperProxy],
 *    [SecurityAuditLogger], [UiLanguageManager]) so that Activity recreation never creates
 *    a fail-open leak window.
 */
class ClaudeCageApp : Application() {

    lateinit var auditLogger: SecurityAuditLogger
        private set

    lateinit var uiLanguageManager: UiLanguageManager
        private set

    lateinit var vpnStateMonitor: VpnStateMonitor
        private set

    lateinit var vpnGatekeeperProxy: VpnGatekeeperProxy
        private set

    lateinit var appIconManager: AppIconManager
        private set

    lateinit var accountProfileManager: AccountProfileManager
        private set

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        enforceProcessEnvironmentSpoofing()
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        enforceProcessEnvironmentSpoofing()

        // Initialize singletons once per process lifecycle
        auditLogger = SecurityAuditLogger(this)
        uiLanguageManager = UiLanguageManager(this)
        appIconManager = AppIconManager(this)
        accountProfileManager = AccountProfileManager(this)
        vpnStateMonitor = VpnStateMonitor(this, auditLogger = auditLogger)
        vpnGatekeeperProxy = VpnGatekeeperProxy(vpnStateMonitor, auditLogger)

        // Start monitoring and SOCKS5 gatekeeper proxy immediately
        vpnStateMonitor.startMonitoring()
        vpnGatekeeperProxy.start()
        val port = vpnGatekeeperProxy.listeningPort
        auditLogger.logInfo("Lifecycle", "ClaudeCageApp initialized, Gatekeeper listening on 127.0.0.1:$port")
    }

    override fun onTerminate() {
        super.onTerminate()
        vpnGatekeeperProxy.stop()
        vpnStateMonitor.stopMonitoring()
    }

    private fun enforceProcessEnvironmentSpoofing() {
        enforceUsLocaleAndTimezone(baseContext ?: this)
        Log.i(TAG, "Process environment isolated to TimeZone=$SPOOFED_TIMEZONE, Locale=en-US")
    }

    companion object {
        private const val TAG = "ClaudeCageApp"
        const val SPOOFED_TIMEZONE = "Europe/Amsterdam"

        lateinit var instance: ClaudeCageApp
            private set

        /**
         * Re-enforces POSIX TZ, JVM TimeZone, and JVM Locale to en-US.
         * Must be invoked whenever Android frameworks or Chromium WebViewFactory reset the locale.
         */
        fun enforceUsLocaleAndTimezone(context: Context? = null) {
            try {
                // Force POSIX environment variable for native libraries and Chromium engine
                Os.setenv("TZ", SPOOFED_TIMEZONE, true)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to setenv TZ: ${e.message}")
            }

            // Force JVM TimeZone
            TimeZone.setDefault(TimeZone.getTimeZone(SPOOFED_TIMEZONE))

            // Force JVM Locale
            Locale.setDefault(Locale.US)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                android.os.LocaleList.setDefault(android.os.LocaleList(Locale.US))
            }

            // Force resource configuration locale to en-US
            context?.let { ctx ->
                try {
                    val resources = ctx.resources
                    val config = resources.configuration
                    config.setLocale(Locale.US)
                    config.setLayoutDirection(Locale.US)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        config.setLocales(android.os.LocaleList(Locale.US))
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to apply configuration locale: ${e.message}")
                }
            }
        }
    }
}
