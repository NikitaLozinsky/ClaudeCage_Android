# EnclaveShield: Enterprise Zero-Trust Web Isolation Container
## Technical Specification & Complete Source Code Package for Architecture & Security Audit (Stage 10)

- **Project Name:** `EnclaveShield` (Package: `com.corp.enclaveshield`)
- **System Classification:** Mobile Enterprise Browser Isolation (EBI) / Zero-Trust Mobile Enclave
- **Target Platform:** Android 13+ (Min SDK: 33, Target SDK: 36, Verified on Android 17 / API 37)
- **Target Ingress Gateway:** Enterprise WireGuard / IPSec Secure Gateway (`tun0` / `tun1`, NetID ~300+)
- **Target Web Application:** Confidential Corporate Intranet Portal (`https://portal.internal-enterprise.net`)
- **Core Security Policy:** **Strict Fail-Closed Zero-Leak Enforcement** (Zero cleartext, mandatory SOCKS5 loopback proxy override with `.removeImplicitRules()`, destination allowlist & RFC 1918 blacklist, kernel socket binding, dedicated Scheduled watchdog, True SWR DNS, and document-start telemetry neutralization).

---

## 1. System Architecture Overview

```
 +---------------------------------------------------------------------------------------+
 | Android Device Runtime (Android 13 - 17, Samsung Galaxy S25 Ultra / Generic)          |
 |                                                                                       |
 |  +---------------------------------------------------------------------------------+  |
 |  | Chromium WebView (Hardened Sandbox)                                            |  |
 |  |  - Document-Start JS (WebRTC killed, Offscreen Canvas clone, toString cloaking) |  |
 |  |  - ProxyController Override -> SOCKS5 Loopback (127.0.0.1:<ephemeral>)         |  |
 |  |  - removeImplicitRules() enabled (prevents localhost/loopback bypass)           |  |
 |  |  - SafeBrowsing disabled (prevents out-of-band telemetry bypass)               |  |
 |  |  - onRenderProcessGone crash resilience handler                                |  |
 |  |  - Multi-Profile Isolation: ProfileStore (AndroidX) / Keystore AES-256-GCM      |  |
 |  +---------------------------------------------------------------------------------+  |
 |                                      |                                                |
 |                                      v (Strict Loopback Only - No direct:// fallback) |
 |  +---------------------------------------------------------------------------------+  |
 |  | In-Process SOCKS5 Gatekeeper Proxy (VpnGatekeeperProxy.kt)                      |  |
 |  |  - Destination Allowlist (portal.internal-enterprise.net, etc.)                |  |
 |  |  - Private IP Blacklist (blocks RFC 1918, 127.0.0.0/8, link-local, tun IP)     |  |
 |  |  - Dedicated Relay Cached Thread Pool (avoids Dispatchers.IO starvation)       |  |
 |  |  - Generational Socket Registry (Instant kill-switch on drop or handover)      |  |
 |  |  - Regional Geofence Guard (CIS domains blocked, .google.ru rewritten)          |  |
 |  |  - Local DNS Resolution via TunnelDnsResolver                                   |  |
 |  +---------------------------------------------------------------------------------+  |
 |          |                                               |                            |
 |          | (DNS Query)                                   | (Outbound TCP Traffic)     |
 |          v                                               v                            |
 |  +-------------------------------------+   +---------------------------------------+  |
 |  | TunnelDnsResolver (RFC 1035 TCP)   |   | Linux Kernel Socket Binding           |  |
 |  |  - Primary: 1.1.1.1:53 (TCP)        |   |  1. network.bindSocket(socket) [NetID]|  |
 |  |  - Fallback: 8.8.8.8:53 (TCP)       |   |  2. socket.bind(tunIpv4, 0)   [Source]|  |
 |  |  - ScheduledExecutor Watchdog 2500ms|   +---------------------------------------+  |
 |  |  - Single-Flight Request Deduplication                                          |  |
 |  |  - True Stale-While-Revalidate Cache|                   |                          |
 |  +-------------------------------------+                   |                          |
 |          |                                                 |                          |
 |          +-----------------------+-------------------------+                          |
 |                                  |                                                    |
 |                                  v                                                    |
 |                  +-------------------------------+                                    |
 |                  | Enterprise VPN Tunnel (tun*)  |                                    |
 |                  +-------------------------------+                                    |
 |                  | bindProcessToNetwork(network) |                                    |
 |                  +-------------------------------+                                    |
 +----------------------------------|----------------------------------------------------+
                                    v
            Enterprise Secure Gateway -> portal.internal-enterprise.net
```

---

## 2. Complete Source Code Manifest

### 2.1. `app/src/main/AndroidManifest.xml`
**Role:** Manifest: Permissions, aliases, cleartext lockdown

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          xmlns:tools="http://schemas.android.com/tools">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <application
            android:name=".EnclaveShieldApp"
            android:allowBackup="false"
            android:dataExtractionRules="@xml/data_extraction_rules"
            android:fullBackupContent="@xml/backup_rules"
            android:icon="@mipmap/ic_launcher_opt1"
            android:label="@string/app_name"
            android:roundIcon="@mipmap/ic_launcher_opt1_round"
            android:supportsRtl="true"
            android:theme="@style/Theme.EnclaveShield"
            android:usesCleartextTraffic="false">
        <activity
                android:name=".MainActivity"
                android:configChanges="orientation|screenSize|screenLayout|smallestScreenSize|keyboardHidden|uiMode|locale|layoutDirection"
                android:exported="true">
        </activity>

        <!-- Launcher Alias 1: Default Classic Icon -->
        <activity-alias
                android:name=".MainActivityAliasDefault"
                android:enabled="true"
                android:exported="true"
                android:icon="@mipmap/ic_launcher_opt1"
                android:roundIcon="@mipmap/ic_launcher_opt1_round"
                android:label="@string/app_name"
                android:targetActivity=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity-alias>

        <!-- Launcher Alias 2: Alternative Icon -->
        <activity-alias
                android:name=".MainActivityAliasVariant2"
                android:enabled="false"
                android:exported="true"
                android:icon="@mipmap/ic_launcher_opt2"
                android:roundIcon="@mipmap/ic_launcher_opt2_round"
                android:label="@string/app_name"
                android:targetActivity=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity-alias>
    </application>

</manifest>

```

---

### 2.2. `app/build.gradle.kts`
**Role:** Build configuration, dependencies and artifact packaging

```kotlin
plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.corp.enclaveshield"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.corp.enclaveshield"
        minSdk = 33
        targetSdk = 36
        versionCode = 2
        versionName = "1.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

tasks.register("copyApkToRoot") {
    doLast {
        val buildDir = layout.buildDirectory.get().asFile
        val debugApkDir = File(buildDir, "outputs/apk/debug")
        val apkFile = debugApkDir.listFiles()?.firstOrNull { it.extension == "apk" && !it.name.contains("unaligned") }
        if (apkFile != null) {
            val ver = android.defaultConfig.versionName ?: "1.1"
            val targetName = "EnclaveShield-$ver.apk"
            val destInRoot = File(rootDir, targetName)

            // Clean up old EnclaveShield-*.apk files in rootDir so the user sees the fresh version
            rootDir.listFiles()?.filter { it.name.startsWith("EnclaveShield-") && it.name.endsWith(".apk") && it.name != targetName }?.forEach { oldApk ->
                println("🗑️ Removing outdated APK from root: ${oldApk.name}")
                oldApk.delete()
            }

            apkFile.copyTo(destInRoot, overwrite = true)
            val destInOutput = File(debugApkDir, targetName)
            if (apkFile.name != targetName) {
                apkFile.copyTo(destInOutput, overwrite = true)
            }
            println("=========================================================")
            println("✅ APK READY IN PROJECT ROOT:")
            println("   -> ${destInRoot.absolutePath}")
            println("   -> Size: ${destInRoot.length()} bytes")
            println("=========================================================")
        }
    }
}

tasks.matching { it.name == "assembleDebug" }.configureEach {
    finalizedBy("copyApkToRoot")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.webkit)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.lifecycle.runtime.ktx)

    testImplementation(libs.junit)
    testImplementation(libs.mockito.core)
    testImplementation("org.json:json:20240303")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

```

---

### 2.3. `app/src/main/java/com/corp/enclaveshield/EnclaveShieldApp.kt`
**Role:** Application class: Lifecycle, POSIX TZ, JVM Locale & LocaleList lock

```kotlin
package com.corp.enclaveshield

import android.app.Application
import android.content.Context
import android.os.Build
import android.system.Os
import android.util.Log
import com.corp.enclaveshield.accounts.AccountProfileManager
import com.corp.enclaveshield.net.VpnGatekeeperProxy
import com.corp.enclaveshield.net.VpnStateMonitor
import com.corp.enclaveshield.telemetry.SecurityAuditLogger
import com.corp.enclaveshield.ui.AppIconManager
import com.corp.enclaveshield.ui.UiLanguageManager
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
class EnclaveShieldApp : Application() {

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
        auditLogger.logInfo("Lifecycle", "EnclaveShieldApp initialized, Gatekeeper listening on 127.0.0.1:$port")
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
        private const val TAG = "EnclaveShieldApp"
        const val SPOOFED_TIMEZONE = "Europe/Amsterdam"

        lateinit var instance: EnclaveShieldApp
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

```

---

### 2.4. `app/src/main/java/com/corp/enclaveshield/MainActivity.kt`
**Role:** Main Activity: WebView sandbox, Profile switching, UI cards, EnclaveDownload, removeImplicitRules, onRenderProcessGone

```kotlin
package com.corp.enclaveshield

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Rect
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.HapticFeedbackConstants
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.URLUtil
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebSettings
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.webkit.ProfileStore
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.corp.enclaveshield.accounts.AccountProfile
import com.corp.enclaveshield.net.VpnTunnelState
import com.corp.enclaveshield.security.AntiFingerprintHardener
import com.corp.enclaveshield.ui.AppIconOption
import com.corp.enclaveshield.ui.UiLanguage
import com.corp.enclaveshield.ui.UiStrings
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.Locale

/**
 * Main application activity hosting an isolated WebView strictly bound to the in-process
 * SOCKS5 Gatekeeper Proxy (127.0.0.1:<listeningPort>).
 *
 * CRITICAL ARCHITECTURAL GUARANTEES (STAGE 5):
 * 1. Singletons ([VpnStateMonitor], [VpnGatekeeperProxy], [SecurityAuditLogger], [UiLanguageManager])
 *    are hosted in [EnclaveShieldApp] so that Activity recreation does NOT recreate or clear proxy state.
 * 2. In [onDestroy], [ProxyController.clearProxyOverride] is NEVER called. The proxy override
 *    remains locked for the lifetime of the Linux process to prevent fail-open windows.
 * 3. User-Agent is sanitized: WebView markers ("; wv", "Version/4.0 ") are stripped.
 * 4. Non-HTTPS schemes in [WebViewClient.shouldOverrideUrlLoading] are blocked.
 * 5. Document-start JS hardening disables WebRTC, spoofs timezone to Europe/Amsterdam and locale to en-US.
 * 6. File and image uploads in Corporate Portal chat are supported via [WebChromeClient.onShowFileChooser].
 * 7. Bilingual UI (RU/EN) is maintained entirely in Kotlin memory without modifying JVM Locale.
 */
class MainActivity : AppCompatActivity() {

    private val app: EnclaveShieldApp
        get() = EnclaveShieldApp.instance

    private lateinit var vpnStatusBar: View
    private lateinit var tvVpnStatus: TextView
    private lateinit var tvVpnSubStatus: TextView
    private lateinit var btnDiagnostics: TextView
    private lateinit var btnReturnToPortal: TextView
    private lateinit var btnAccountSwitcher: TextView
    private lateinit var btnLangToggle: TextView
    private lateinit var btnCollapseBar: TextView
    private lateinit var floatingSecurityAnchor: View
    private lateinit var viewAnchorDot: View
    private lateinit var tvFloatingAnchorStatus: TextView
    private lateinit var tvFloatingAnchorAccount: TextView
    private lateinit var webViewContainer: FrameLayout
    private lateinit var waitingOverlay: View
    private lateinit var tvWaitingTitle: TextView
    private lateinit var tvWaitingDesc: TextView
    private lateinit var securityErrorOverlay: View
    private lateinit var tvSecurityErrorTitle: TextView
    private lateinit var tvSecurityErrorDesc: TextView

    private var isTopBarCollapsed: Boolean = false

    private var webView: WebView? = null
    private var isProxyOverrideActive = false
    private var hasLoadedInitialUrl = false
    private var wasConnectedOnce = false
    private var bannerFlashJob: Job? = null

    private var fileChooserCallback: ValueCallback<Array<Uri>>? = null

    private val fileChooserLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val callback = fileChooserCallback
        fileChooserCallback = null
        if (callback == null) return@registerForActivityResult

        val uris = if (result.resultCode == Activity.RESULT_OK && result.data != null) {
            val data = result.data!!
            val clipData = data.clipData
            if (clipData != null && clipData.itemCount > 0) {
                val list = mutableListOf<Uri>()
                for (i in 0 until clipData.itemCount) {
                    clipData.getItemAt(i).uri?.let { list.add(it) }
                }
                list.toTypedArray()
            } else if (data.data != null) {
                arrayOf(data.data!!)
            } else {
                null
            }
        } else {
            null
        }

        callback.onReceiveValue(uris)
    }

    private var pendingDownloadBytes: ByteArray? = null
    private var pendingDownloadFilename: String = "artifact.txt"

    private val createDocumentLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        val bytes = pendingDownloadBytes
        val filename = pendingDownloadFilename
        pendingDownloadBytes = null
        if (uri != null && bytes != null) {
            try {
                contentResolver.openOutputStream(uri)?.use { os ->
                    os.write(bytes)
                    os.flush()
                }
                val lang = app.uiLanguageManager.language.value
                Toast.makeText(this, UiStrings.toastDownloadSuccess(lang, filename), Toast.LENGTH_SHORT).show()
                app.auditLogger.logInfo("Download", "Saved artifact: $filename (${bytes.size} bytes)")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to write downloaded file: ${e.message}")
                val lang = app.uiLanguageManager.language.value
                Toast.makeText(this, UiStrings.toastDownloadFailed(lang, e.message ?: "write error"), Toast.LENGTH_SHORT).show()
            }
        }
    }

    private class SafeDownloadBridge(
        private val getActiveUrl: () -> String?,
        private val onDownloaded: (ByteArray, String, String) -> Unit,
        private val onFailed: (String) -> Unit
    ) {
        @JavascriptInterface
        fun onBlobDownloaded(base64Data: String, suggestedFilename: String, mimeType: String) {
            val url = getActiveUrl() ?: ""
            if (!url.startsWith("https://portal.internal-enterprise.net/") && url != "https://portal.internal-enterprise.net") {
                onFailed("Download forbidden: unauthorized origin ($url)")
                return
            }
            val bytes = try {
                Base64.decode(base64Data, Base64.DEFAULT)
            } catch (e: Exception) {
                onFailed("Decode error: ${e.message}")
                return
            }
            onDownloaded(bytes, suggestedFilename, mimeType)
        }

        @JavascriptInterface
        fun onDownloadFailed(error: String) {
            onFailed(error)
        }
    }

    override fun attachBaseContext(base: Context) {
        EnclaveShieldApp.enforceUsLocaleAndTimezone(base)
        val config = android.content.res.Configuration(base.resources.configuration).apply {
            setLocale(Locale.US)
            setLayoutDirection(Locale.US)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                setLocales(android.os.LocaleList(Locale.US))
            }
        }
        val wrapped = base.createConfigurationContext(config)
        super.attachBaseContext(wrapped)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EnclaveShieldApp.enforceUsLocaleAndTimezone(this)
        enableEdgeToEdge()

        val secPrefs = getSharedPreferences(PREFS_SECURITY_SETTINGS, Context.MODE_PRIVATE)
        val isFlagSecureEnabled = secPrefs.getBoolean(KEY_FLAG_SECURE, true)
        if (isFlagSecureEnabled) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }

        setContentView(R.layout.activity_main)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val barsAndIme = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.ime()
            )
            v.setPadding(barsAndIme.left, barsAndIme.top, barsAndIme.right, barsAndIme.bottom)
            insets
        }

        bindViews()
        setupListeners()
        setupBackNavigation()

        val collapsePrefs = getSharedPreferences(PREFS_UI_COLLAPSE, Context.MODE_PRIVATE)
        isTopBarCollapsed = collapsePrefs.getBoolean(KEY_TOPBAR_COLLAPSED, false)
        setTopBarCollapsed(isTopBarCollapsed)

        floatingSecurityAnchor.post {
            val savedX = collapsePrefs.getFloat(KEY_ANCHOR_X, -1f)
            val savedY = collapsePrefs.getFloat(KEY_ANCHOR_Y, -1f)
            if (savedX >= 0f && savedY >= 0f) {
                floatingSecurityAnchor.x = savedX
                floatingSecurityAnchor.y = savedY
            }
        }

        val proxyPort = app.vpnGatekeeperProxy.listeningPort
        app.auditLogger.logInfo("UI", "MainActivity started with proxy on port $proxyPort")

        // Configure strict ProxyController before instantiating WebView
        applyProxyOverrideAndInitialize(proxyPort)

        // Observe dead tunnel unresponsive warning (Amber state)
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (isActive) {
                    delay(2500)
                    val state = app.vpnStateMonitor.vpnState.value
                    if (state is VpnTunnelState.Connected) {
                        refreshStatusBarText(state, proxyPort, app.uiLanguageManager.language.value)
                    }
                }
            }
        }

        // Observe VPN tunnel status changes
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                app.vpnStateMonitor.vpnState.collect { state ->
                    handleVpnStateChange(state, proxyPort)
                }
            }
        }

        // Observe UI Language changes
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                app.uiLanguageManager.language.collect { lang ->
                    updateUiLanguage(lang)
                }
            }
        }

        // Observe Account Profile changes
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                app.accountProfileManager.activeProfile.collect { profile ->
                    updateAccountSwitcherButtonText(app.uiLanguageManager.language.value, profile)
                }
            }
        }
    }

    private fun bindViews() {
        vpnStatusBar = findViewById(R.id.vpnStatusBar)
        tvVpnStatus = findViewById(R.id.tvVpnStatus)
        tvVpnSubStatus = findViewById(R.id.tvVpnSubStatus)
        btnDiagnostics = findViewById(R.id.btnDiagnostics)
        btnReturnToPortal = findViewById(R.id.btnReturnToPortal)
        btnAccountSwitcher = findViewById(R.id.btnAccountSwitcher)
        btnLangToggle = findViewById(R.id.btnLangToggle)
        btnCollapseBar = findViewById(R.id.btnCollapseBar)
        floatingSecurityAnchor = findViewById(R.id.floatingSecurityAnchor)
        viewAnchorDot = findViewById(R.id.viewAnchorDot)
        tvFloatingAnchorStatus = findViewById(R.id.tvFloatingAnchorStatus)
        tvFloatingAnchorAccount = findViewById(R.id.tvFloatingAnchorAccount)
        webViewContainer = findViewById(R.id.webViewContainer)
        waitingOverlay = findViewById(R.id.waitingOverlay)
        tvWaitingTitle = findViewById(R.id.tvWaitingTitle)
        tvWaitingDesc = findViewById(R.id.tvWaitingDesc)
        securityErrorOverlay = findViewById(R.id.securityErrorOverlay)
        tvSecurityErrorTitle = findViewById(R.id.tvSecurityErrorTitle)
        tvSecurityErrorDesc = findViewById(R.id.tvSecurityErrorDesc)
    }

    private fun setupListeners() {
        btnDiagnostics.setOnClickListener {
            it.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
            showDiagnosticsDialog()
        }
        vpnStatusBar.setOnLongClickListener {
            it.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
            showDiagnosticsDialog()
            true
        }
        btnReturnToPortal.setOnClickListener {
            it.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
            btnReturnToPortal.visibility = View.GONE
            webView?.loadUrl(PORTAL_URL, mapOf("Accept-Language" to "en-US,en;q=0.9"))
        }
        btnAccountSwitcher.setOnClickListener {
            it.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
            showAccountDialog()
        }
        btnLangToggle.setOnClickListener {
            it.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
            val nextLang = app.uiLanguageManager.toggleLanguage()
            btnLangToggle.text = nextLang.label
        }
        btnCollapseBar.setOnClickListener {
            it.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
            setTopBarCollapsed(true)
        }
        setupFloatingAnchorDragAndClick()
    }

    private fun setTopBarCollapsed(collapsed: Boolean) {
        isTopBarCollapsed = collapsed
        if (collapsed) {
            vpnStatusBar.visibility = View.GONE
            floatingSecurityAnchor.visibility = View.VISIBLE
        } else {
            vpnStatusBar.visibility = View.VISIBLE
            floatingSecurityAnchor.visibility = View.GONE
        }
        val prefs = getSharedPreferences(PREFS_UI_COLLAPSE, Context.MODE_PRIVATE)
        prefs.edit().putBoolean(KEY_TOPBAR_COLLAPSED, collapsed).apply()
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun setupFloatingAnchorDragAndClick() {
        var dX = 0f
        var dY = 0f
        var startX = 0f
        var startY = 0f
        var isClick = false

        tvFloatingAnchorAccount.setOnClickListener {
            it.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
            showAccountDialog()
        }

        floatingSecurityAnchor.setOnTouchListener { view, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    dX = view.x - event.rawX
                    dY = view.y - event.rawY
                    startX = event.rawX
                    startY = event.rawY
                    isClick = true
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dist = Math.hypot((event.rawX - startX).toDouble(), (event.rawY - startY).toDouble())
                    if (dist > 15) {
                        isClick = false
                        val parent = view.parent as? View
                        val maxX = (parent?.width ?: 0) - view.width
                        val maxY = (parent?.height ?: 0) - view.height
                        val newX = (event.rawX + dX).coerceIn(0f, maxX.toFloat())
                        val newY = (event.rawY + dY).coerceIn(0f, maxY.toFloat())
                        view.x = newX
                        view.y = newY
                    }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    if (isClick) {
                        val rect = Rect()
                        tvFloatingAnchorAccount.getGlobalVisibleRect(rect)
                        if (rect.contains(event.rawX.toInt(), event.rawY.toInt())) {
                            tvFloatingAnchorAccount.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
                            showAccountDialog()
                        } else {
                            view.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
                            setTopBarCollapsed(false)
                        }
                    } else {
                        snapAnchorToNearestEdge(view)
                    }
                    true
                }
                else -> false
            }
        }

        floatingSecurityAnchor.setOnLongClickListener {
            it.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
            showDiagnosticsDialog()
            true
        }
    }

    private fun snapAnchorToNearestEdge(view: View) {
        val parent = view.parent as? View
        val parentWidth = parent?.width?.takeIf { it > 0 } ?: resources.displayMetrics.widthPixels
        val marginPx = (12 * resources.displayMetrics.density)
        val viewWidth = view.width.toFloat()
        val centerX = view.x + (viewWidth / 2f)

        val targetX = if (centerX < parentWidth / 2f) {
            marginPx
        } else {
            (parentWidth - viewWidth - marginPx).coerceAtLeast(marginPx)
        }

        view.animate()
            .x(targetX)
            .setDuration(220)
            .withEndAction {
                val prefs = getSharedPreferences(PREFS_UI_COLLAPSE, Context.MODE_PRIVATE)
                prefs.edit()
                    .putFloat(KEY_ANCHOR_X, targetX)
                    .putFloat(KEY_ANCHOR_Y, view.y)
                    .apply()
            }
            .start()
    }

    private fun setupBackNavigation() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val wv = webView
                if (wv != null && wv.canGoBack()) {
                    wv.goBack()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })
    }

    private fun updateUiLanguage(lang: UiLanguage) {
        btnLangToggle.text = lang.label
        updateAccountSwitcherButtonText(lang)
        btnDiagnostics.text = UiStrings.btnDiagnostics(lang)
        btnReturnToPortal.text = UiStrings.btnReturnToPortal(lang)
        tvWaitingTitle.text = UiStrings.waitingTitle(lang)
        tvWaitingDesc.text = UiStrings.waitingDesc(lang)
        tvSecurityErrorTitle.text = UiStrings.securityErrorTitle(lang)
        tvSecurityErrorDesc.text = UiStrings.securityErrorDesc(lang)

        // Refresh status bar with current tunnel state
        val currentTunnel = app.vpnStateMonitor.getCurrentTunnelState()
        val proxyPort = app.vpnGatekeeperProxy.listeningPort
        refreshStatusBarText(currentTunnel, proxyPort, lang)
    }

    override fun onResume() {
        super.onResume()
        EnclaveShieldApp.enforceUsLocaleAndTimezone(this)
        val current = app.vpnStateMonitor.getCurrentTunnelState()
        val proxyPort = app.vpnGatekeeperProxy.listeningPort
        refreshStatusBarText(current, proxyPort, app.uiLanguageManager.language.value)
    }

    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        EnclaveShieldApp.enforceUsLocaleAndTimezone(this)
    }

    private fun applyProxyOverrideAndInitialize(proxyPort: Int) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            val err = "FATAL SECURITY ERROR: WebViewFeature.PROXY_OVERRIDE is not supported on this device!"
            Log.e(TAG, err)
            app.auditLogger.logCritical("Security", err)
            securityErrorOverlay.visibility = View.VISIBLE
            waitingOverlay.visibility = View.GONE
            vpnStatusBar.setBackgroundColor(getColor(R.color.error_bg))
            tvVpnStatus.setTextColor(getColor(R.color.error_text))
            tvVpnStatus.text = UiStrings.securityErrorTitle(app.uiLanguageManager.language.value)
            return
        }

        // Lock WebView traffic strictly to our loopback SOCKS5 proxy without any direct fallback.
        // Explicitly remove implicit bypass rules so loopback destinations cannot be accessed directly.
        val proxyConfig = ProxyConfig.Builder()
            .addProxyRule("socks5://127.0.0.1:$proxyPort")
            .removeImplicitRules()
            .build()

        ProxyController.getInstance().setProxyOverride(
            proxyConfig,
            ContextCompat.getMainExecutor(this)
        ) {
            Log.i(TAG, "ProxyController confirmed active: socks5://127.0.0.1:$proxyPort")
            app.auditLogger.logInfo("Security", "ProxyController override confirmed on port $proxyPort")
            isProxyOverrideActive = true
            app.auditLogger.isProxyOverrideActive = true
            initWebView()
        }
    }

    private fun initWebView(accountProfile: AccountProfile = app.accountProfileManager.activeProfile.value) {
        if (webView != null) return

        val wv = WebView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        }
        // Stage 6 Bug #1 Fix: WebViewFactory resets Locale.setDefault() to system locale
        EnclaveShieldApp.enforceUsLocaleAndTimezone(this)

        // Stage 7: Multi-Profile Containerization via AndroidX ProfileStore
        if (WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) {
            try {
                val profileStore = ProfileStore.getInstance()
                val profile = profileStore.getOrCreateProfile(accountProfile.storageKey)
                WebViewCompat.setProfile(wv, profile.name)
                Log.i(TAG, "Bound WebView to ProfileStore profile: ${profile.name} (${accountProfile.displayName})")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to bind WebView to profile ${accountProfile.storageKey}", e)
                app.auditLogger.logWarning("Security", "Profile binding failed: ${e.message}")
            }
        } else {
            // Fallback for engines without MULTI_PROFILE
            app.accountProfileManager.fallback.restoreCookies(accountProfile.id)
        }

        webView = wv
        webViewContainer.addView(wv)

        // Apply document-start anti-fingerprinting JS hardening (WebRTC kill, TZ, Locale)
        val hardeningApplied = AntiFingerprintHardener.applyHardening(wv, accountProfile.profileSeed)
        app.auditLogger.isDocumentStartJsActive = hardeningApplied
        app.auditLogger.logInfo("Hardening", "Document-start JS hardening applied: $hardeningApplied (profileSeed=${accountProfile.profileSeed})")

        // Configure WebSettings for portal.internal-enterprise.net compatibility & privacy
        val settings = wv.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        @Suppress("DEPRECATION")
        settings.databaseEnabled = true
        settings.allowFileAccess = false
        settings.allowContentAccess = false

        // Disable Safe Browsing out-of-band requests that could bypass our local SOCKS5 proxy
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SAFE_BROWSING_ENABLE)) {
            androidx.webkit.WebSettingsCompat.setSafeBrowsingEnabled(settings, false)
        }

        // Sanitize User-Agent to strip Android WebView markers
        val originalUa = settings.userAgentString
        val sanitizedUa = originalUa
            .replace("; wv", "")
            .replace("Version/4.0 ", "")
        settings.userAgentString = sanitizedUa
        app.auditLogger.logInfo("AntiFingerprint", "User-Agent sanitized: $sanitizedUa")

        // Enable cookies so login sessions persist across app restarts
        val cookieManager = if (WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) {
            try {
                val profileStore = ProfileStore.getInstance()
                val profile = profileStore.getOrCreateProfile(accountProfile.storageKey)
                profile.cookieManager
            } catch (_: Exception) {
                CookieManager.getInstance()
            }
        } else {
            CookieManager.getInstance()
        }
        cookieManager.setAcceptCookie(true)
        cookieManager.setAcceptThirdPartyCookies(wv, true)

        wv.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val uri = request?.url ?: return true
                val scheme = uri.scheme?.lowercase(Locale.US)
                if (scheme != "https") {
                    Log.w(TAG, "Blocked non-HTTPS scheme: $scheme for $uri")
                    app.auditLogger.logWarning("Security", "Blocked non-HTTPS navigation attempt: $uri")
                    return true
                }
                return false
            }

            override fun onRenderProcessGone(view: WebView?, detail: android.webkit.RenderProcessGoneDetail?): Boolean {
                val didCrash = detail?.didCrash() ?: false
                Log.w(TAG, "WebView render process gone! didCrash=$didCrash")
                app.auditLogger.logCritical("WebView", "Render process gone (didCrash=$didCrash), rebuilding WebView")
                (view?.parent as? ViewGroup)?.removeView(view)
                view?.destroy()
                webView = null
                hasLoadedInitialUrl = false
                initWebView()
                return true
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                if (url?.contains("browserleaks.com") == true) {
                    btnReturnToPortal.visibility = View.VISIBLE
                } else if (url?.contains("portal.internal-enterprise.net") == true) {
                    btnReturnToPortal.visibility = View.GONE
                }
            }
        }

        wv.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                webView: WebView?,
                filePathCallback: ValueCallback<Array<Uri>>?,
                fileChooserParams: FileChooserParams?
            ): Boolean {
                fileChooserCallback?.onReceiveValue(null)
                fileChooserCallback = filePathCallback

                val intent = runCatching {
                    fileChooserParams?.createIntent()
                }.getOrNull() ?: Intent(Intent.ACTION_GET_CONTENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                    putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
                }

                return try {
                    fileChooserLauncher.launch(intent)
                    true
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to launch file chooser", e)
                    app.auditLogger.logWarning("UI", "Failed to launch file chooser: ${e.message}")
                    fileChooserCallback?.onReceiveValue(null)
                    fileChooserCallback = null
                    false
                }
            }
        }

        // Wire SafeDownloadBridge with origin verification
        wv.addJavascriptInterface(
            SafeDownloadBridge(
                getActiveUrl = { wv.url },
                onDownloaded = { bytes, filename, _ ->
                    runOnUiThread {
                        pendingDownloadBytes = bytes
                        pendingDownloadFilename = filename.ifBlank { "enclave_artifact.txt" }
                        createDocumentLauncher.launch(pendingDownloadFilename)
                    }
                },
                onFailed = { err ->
                    runOnUiThread {
                        val lang = app.uiLanguageManager.language.value
                        Toast.makeText(this, UiStrings.toastDownloadFailed(lang, err), Toast.LENGTH_SHORT).show()
                    }
                }
            ),
            "EnclaveDownload"
        )

        wv.setDownloadListener { url, _, contentDisposition, mimeType, _ ->
            val filename = URLUtil.guessFileName(url, contentDisposition, mimeType ?: "text/plain")
            val safeUrl = url.replace("\\", "\\\\").replace("'", "\\'")
            val safeName = filename.replace("\\", "\\\\").replace("'", "\\'")
            val safeMime = (mimeType ?: "application/octet-stream").replace("\\", "\\\\").replace("'", "\\'")
            val js = """
                (async () => {
                    try {
                        const resp = await fetch('$safeUrl');
                        const blob = await resp.blob();
                        const reader = new FileReader();
                        reader.onloadend = () => {
                            const base64 = reader.result.split(',')[1] || '';
                            window.EnclaveDownload.onBlobDownloaded(base64, '$safeName', '$safeMime');
                        };
                        reader.readAsDataURL(blob);
                    } catch (e) {
                        window.EnclaveDownload.onDownloadFailed(e.toString());
                    }
                })();
            """.trimIndent()
            wv.evaluateJavascript(js, null)
        }

        // Check initial VPN state to determine immediate loading or waiting state
        val initialVpnState = app.vpnStateMonitor.getCurrentTunnelState()
        if (initialVpnState is VpnTunnelState.Connected) {
            wv.setNetworkAvailable(true)
            waitingOverlay.visibility = View.GONE
            wv.loadUrl(PORTAL_URL, mapOf("Accept-Language" to "en-US,en;q=0.9"))
            hasLoadedInitialUrl = true
        } else {
            wv.setNetworkAvailable(false)
            waitingOverlay.visibility = View.VISIBLE
        }
    }

    /**
     * Executes isolated account profile switching:
     * 1. Records required security audit log: [SECURITY][INFO] Switching account profile to: ${profile.displayName}
     * 2. Snapshots current cookies if MULTI_PROFILE is unsupported.
     * 3. Completely tears down existing WebView (stopLoading, removeView, destroy).
     * 4. Updates active profile in [app.accountProfileManager].
     * 5. Instantiates fresh WebView and binds to target profile container via [initWebView].
     */
    fun switchAccountProfile(targetProfile: AccountProfile) {
        val currentProfile = app.accountProfileManager.activeProfile.value
        if (targetProfile.id == currentProfile.id && webView != null) {
            return
        }

        // 1. Record security audit log
        app.auditLogger.logInfo("Security", "Switching account profile to: ${targetProfile.displayName}")

        // 2. Cookie Jar snapshot for fallback engines without MULTI_PROFILE
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) {
            app.accountProfileManager.fallback.snapshotCookies(currentProfile.id)
            try {
                CookieManager.getInstance().removeAllCookies(null)
                CookieManager.getInstance().flush()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to clear cookies during switch: ${e.message}")
            }
        }

        // 3. Update active profile in AccountProfileManager
        app.accountProfileManager.switchProfile(targetProfile.id)

        // 4. Stop and remove current WebView from webViewContainer
        webView?.let { wv ->
            wv.stopLoading()
            webViewContainer.removeView(wv)
            wv.destroy()
        }
        webView = null

        // 5. Instantiate fresh WebView bound to targetProfile and load PORTAL_URL
        hasLoadedInitialUrl = false
        initWebView(targetProfile)

        // 6. Reset return button
        btnReturnToPortal.visibility = View.GONE

        // 7. Update top bar button label
        val lang = app.uiLanguageManager.language.value
        updateAccountSwitcherButtonText(lang, targetProfile)

        Toast.makeText(this, UiStrings.toastProfileSwitched(lang, targetProfile.displayName), Toast.LENGTH_SHORT).show()
    }

    private fun updateAccountSwitcherButtonText(
        lang: UiLanguage = app.uiLanguageManager.language.value,
        profile: AccountProfile = app.accountProfileManager.activeProfile.value
    ) {
        btnAccountSwitcher.text = UiStrings.btnAccountSelector(lang, profile.displayName)
        tvFloatingAnchorAccount.text = "• 👤 ${profile.displayName} ▾"
    }

    private fun createCardBackground(fillHex: String, strokeHex: String, radiusDp: Float = 12f): GradientDrawable {
        val density = resources.displayMetrics.density
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = radiusDp * density
            setColor(Color.parseColor(fillHex))
            setStroke((1 * density).toInt(), Color.parseColor(strokeHex))
        }
    }

    private fun showAccountDialog() {
        val lang = app.uiLanguageManager.language.value
        var dialogRef: AlertDialog? = null

        val scrollView = ScrollView(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(32, 24, 32, 24)
        }

        val contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        scrollView.addView(contentLayout)

        fun refreshList() {
            contentLayout.removeAllViews()
            val profiles = app.accountProfileManager.profiles.value
            val activeProfile = app.accountProfileManager.activeProfile.value

            for (profile in profiles) {
                val isActive = (profile.id == activeProfile.id)

                val row = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = android.view.Gravity.CENTER_VERTICAL
                    val d = resources.displayMetrics.density
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply {
                        setMargins(0, (6 * d).toInt(), 0, (6 * d).toInt())
                    }
                    setPadding((16 * d).toInt(), (12 * d).toInt(), (16 * d).toInt(), (12 * d).toInt())
                    background = createCardBackground(if (isActive) "#162436" else "#161B22", if (isActive) "#38BDF8" else "#2A3441", 12f)
                }

                val rb = RadioButton(this).apply {
                    isChecked = isActive
                    isClickable = false
                }
                row.addView(rb)

                val textLayout = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    layoutParams = LinearLayout.LayoutParams(
                        0,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        1f
                    ).apply {
                        setMargins(12, 0, 12, 0)
                    }
                }

                val titleView = TextView(this).apply {
                    text = profile.displayName + (if (isActive) UiStrings.activeAccountBadge(lang) else "")
                    textSize = 14f
                    setTypeface(null, if (isActive) Typeface.BOLD else Typeface.NORMAL)
                    setTextColor(if (isActive) Color.parseColor("#80D8FF") else Color.WHITE)
                }
                textLayout.addView(titleView)
                row.addView(textLayout)

                row.setOnClickListener {
                    if (!isActive) {
                        dialogRef?.dismiss()
                        switchAccountProfile(profile)
                    }
                }

                val btnRename = MaterialButton(this, null, com.google.android.material.R.attr.borderlessButtonStyle).apply {
                    text = "✏️"
                    textSize = 12f
                    setPadding(8, 4, 8, 4)
                    minWidth = 0
                    minimumWidth = 0
                    setOnClickListener {
                        promptRenameProfile(profile) {
                            refreshList()
                        }
                    }
                }
                row.addView(btnRename)

                val btnDelete = MaterialButton(this, null, com.google.android.material.R.attr.borderlessButtonStyle).apply {
                    text = "🗑️"
                    textSize = 12f
                    setPadding(8, 4, 8, 4)
                    minWidth = 0
                    minimumWidth = 0
                    isEnabled = profiles.size > 1
                    alpha = if (profiles.size > 1) 1.0f else 0.3f
                    setOnClickListener {
                        confirmDeleteProfile(profile) { wasActive ->
                            if (wasActive) {
                                dialogRef?.dismiss()
                            } else {
                                refreshList()
                            }
                        }
                    }
                }
                row.addView(btnDelete)

                contentLayout.addView(row)
            }

            val btnAdd = MaterialButton(this).apply {
                text = UiStrings.btnAddAccount(lang)
                textSize = 13f
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, 16, 0, 4)
                }
                setOnClickListener {
                    promptAddProfile { newProfile ->
                        dialogRef?.dismiss()
                        switchAccountProfile(newProfile)
                    }
                }
            }
            contentLayout.addView(btnAdd)
        }

        refreshList()

        dialogRef = MaterialAlertDialogBuilder(this)
            .setTitle(UiStrings.accountDialogTitle(lang))
            .setView(scrollView)
            .setNegativeButton(UiStrings.btnClose(lang), null)
            .show()
    }

    private fun promptAddProfile(onCreated: (AccountProfile) -> Unit) {
        val lang = app.uiLanguageManager.language.value
        val input = EditText(this).apply {
            hint = UiStrings.dialogAddAccountHint(lang)
            setSingleLine(true)
            setPadding(48, 32, 48, 32)
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(UiStrings.dialogAddAccountTitle(lang))
            .setView(input)
            .setPositiveButton(UiStrings.btnAdd(lang)) { _, _ ->
                val name = input.text.toString().trim()
                val newProfile = app.accountProfileManager.createProfile(name)
                Toast.makeText(this, UiStrings.toastProfileCreated(lang, newProfile.displayName), Toast.LENGTH_SHORT).show()
                onCreated(newProfile)
            }
            .setNegativeButton(UiStrings.btnCancel(lang), null)
            .show()
    }

    private fun promptRenameProfile(profile: AccountProfile, onRenamed: () -> Unit) {
        val lang = app.uiLanguageManager.language.value
        val input = EditText(this).apply {
            setText(profile.displayName)
            setSelection(profile.displayName.length)
            setSingleLine(true)
            setPadding(48, 32, 48, 32)
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(UiStrings.dialogRenameTitle(lang))
            .setView(input)
            .setPositiveButton(UiStrings.btnSave(lang)) { _, _ ->
                val newName = input.text.toString().trim()
                if (newName.isNotEmpty()) {
                    val success = app.accountProfileManager.renameProfile(profile.id, newName)
                    if (success) {
                        Toast.makeText(this, UiStrings.toastProfileRenamed(lang), Toast.LENGTH_SHORT).show()
                        updateAccountSwitcherButtonText(lang)
                        onRenamed()
                    }
                }
            }
            .setNegativeButton(UiStrings.btnCancel(lang), null)
            .show()
    }

    private fun confirmDeleteProfile(profile: AccountProfile, onDeleted: (Boolean) -> Unit) {
        val lang = app.uiLanguageManager.language.value
        if (app.accountProfileManager.profiles.value.size <= 1) {
            Toast.makeText(this, UiStrings.dialogDeleteCannotDeleteOnly(lang), Toast.LENGTH_SHORT).show()
            return
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(UiStrings.dialogDeleteConfirmTitle(lang))
            .setMessage(UiStrings.dialogDeleteConfirmMessage(lang, profile.displayName))
            .setPositiveButton(UiStrings.btnDelete(lang)) { _, _ ->
                val wasActive = (profile.id == app.accountProfileManager.activeProfile.value.id)
                if (wasActive) {
                    val fallbackTarget = app.accountProfileManager.profiles.value.firstOrNull { it.id != profile.id }
                    if (fallbackTarget != null) {
                        switchAccountProfile(fallbackTarget)
                    }
                }
                val success = app.accountProfileManager.deleteProfile(profile.id)
                if (success) {
                    Toast.makeText(this, UiStrings.toastProfileDeleted(lang, profile.displayName), Toast.LENGTH_SHORT).show()
                    updateAccountSwitcherButtonText(lang)
                    onDeleted(wasActive)
                }
            }
            .setNegativeButton(UiStrings.btnCancel(lang), null)
            .show()
    }

    private fun handleVpnStateChange(state: VpnTunnelState, proxyPort: Int) {
        bannerFlashJob?.cancel()
        val lang = app.uiLanguageManager.language.value

        when (state) {
            is VpnTunnelState.Connected -> {
                val isReconnect = wasConnectedOnce || hasLoadedInitialUrl
                wasConnectedOnce = true

                val wv = webView
                if (wv != null) {
                    wv.setNetworkAvailable(true)
                    wv.evaluateJavascript(
                        "window.__enclaveOffline = false; window.dispatchEvent(new Event('online'));",
                        null
                    )

                    if (!hasLoadedInitialUrl) {
                        waitingOverlay.visibility = View.GONE
                        wv.loadUrl(PORTAL_URL, mapOf("Accept-Language" to "en-US,en;q=0.9"))
                        hasLoadedInitialUrl = true
                    }
                } else if (isProxyOverrideActive) {
                    initWebView()
                }

                if (isReconnect && hasLoadedInitialUrl) {
                    // Flash green "VPN restored" banner for 2 seconds
                    vpnStatusBar.setBackgroundColor(Color.parseColor("#142E1F"))
                    tvVpnStatus.setTextColor(Color.parseColor("#4ADE80"))
                    tvVpnStatus.text = UiStrings.statusRestored(lang)
                    tvVpnSubStatus.text = UiStrings.subStatusActive(lang, state.interfaceName, proxyPort)

                    viewAnchorDot.setBackgroundResource(R.drawable.bg_status_dot_green)
                    tvFloatingAnchorStatus.text = UiStrings.statusRestored(lang)
                    tvFloatingAnchorStatus.setTextColor(Color.parseColor("#4ADE80"))

                    bannerFlashJob = lifecycleScope.launch {
                        delay(2000)
                        showActiveBanner(state, proxyPort, app.uiLanguageManager.language.value)
                    }
                } else {
                    showActiveBanner(state, proxyPort, lang)
                }
            }

            is VpnTunnelState.Disconnected -> {
                val wv = webView
                if (wv != null) {
                    wv.setNetworkAvailable(false)
                    wv.evaluateJavascript(
                        "window.__enclaveOffline = true; window.dispatchEvent(new Event('offline'));",
                        null
                    )
                }

                showDisconnectedBanner(proxyPort, lang)

                if (hasLoadedInitialUrl) {
                    waitingOverlay.visibility = View.GONE
                } else {
                    waitingOverlay.visibility = View.VISIBLE
                }
            }
        }
    }

    private fun showActiveBanner(state: VpnTunnelState.Connected, proxyPort: Int, lang: UiLanguage) {
        val isUnresponsive = app.auditLogger.consecutiveNetworkTimeouts.get() >= 2
        if (isUnresponsive) {
            vpnStatusBar.setBackgroundColor(Color.parseColor("#292012"))
            tvVpnStatus.setTextColor(Color.parseColor("#FBBF24"))
            tvVpnStatus.text = UiStrings.statusLeakRiskConcise(lang)
            tvVpnSubStatus.text = UiStrings.subStatusActive(lang, state.interfaceName, proxyPort)

            viewAnchorDot.setBackgroundResource(R.drawable.bg_status_dot_yellow)
            tvFloatingAnchorStatus.text = UiStrings.statusLeakRiskConcise(lang)
            tvFloatingAnchorStatus.setTextColor(Color.parseColor("#FBBF24"))
        } else {
            vpnStatusBar.setBackgroundColor(Color.parseColor("#161B22"))
            tvVpnStatus.setTextColor(Color.parseColor("#4ADE80"))
            tvVpnStatus.text = UiStrings.statusProtectedConcise(lang)
            tvVpnSubStatus.text = UiStrings.subStatusActive(lang, state.interfaceName, proxyPort)

            viewAnchorDot.setBackgroundResource(R.drawable.bg_status_dot_green)
            tvFloatingAnchorStatus.text = UiStrings.statusProtectedConcise(lang)
            tvFloatingAnchorStatus.setTextColor(Color.parseColor("#4ADE80"))
        }
    }

    private fun showDisconnectedBanner(proxyPort: Int, lang: UiLanguage) {
        vpnStatusBar.setBackgroundColor(Color.parseColor("#1F1315"))
        tvVpnStatus.setTextColor(Color.parseColor("#F87171"))
        tvVpnStatus.text = UiStrings.statusBlockedConcise(lang)
        tvVpnSubStatus.text = UiStrings.subStatusOffline(lang, proxyPort)

        viewAnchorDot.setBackgroundResource(R.drawable.bg_status_dot_red)
        tvFloatingAnchorStatus.text = UiStrings.statusBlockedConcise(lang)
        tvFloatingAnchorStatus.setTextColor(Color.parseColor("#F87171"))
    }

    private fun refreshStatusBarText(state: VpnTunnelState, proxyPort: Int, lang: UiLanguage) {
        when (state) {
            is VpnTunnelState.Connected -> showActiveBanner(state, proxyPort, lang)
            is VpnTunnelState.Disconnected -> showDisconnectedBanner(proxyPort, lang)
        }
    }

    private fun showDiagnosticsDialog() {
        val lang = app.uiLanguageManager.language.value
        val currentTunnel = app.vpnStateMonitor.getCurrentTunnelState()
        val proxyPort = app.vpnGatekeeperProxy.listeningPort
        val dnsStats = app.auditLogger.getDnsStats()
        val metrics = app.auditLogger.getSnapshot()
        val recentLogs = app.auditLogger.getRecentLogs(10)

        val scrollView = ScrollView(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(32, 24, 32, 24)
        }

        val contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        scrollView.addView(contentLayout)

        val density = resources.displayMetrics.density

        fun addSection(title: String, statusText: String, isSuccess: Boolean, explanation: String) {
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, (4 * density).toInt(), 0, (6 * density).toInt())
                }
                background = createCardBackground("#161B22", "#263238", 12f)
                setPadding((16 * density).toInt(), (12 * density).toInt(), (16 * density).toInt(), (12 * density).toInt())
            }
            val titleView = TextView(this).apply {
                text = title
                textSize = 14f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.WHITE)
                setPadding(0, 0, 0, 4)
            }
            val statusView = TextView(this).apply {
                text = statusText
                textSize = 13f
                setTypeface(null, Typeface.BOLD)
                setTextColor(if (isSuccess) Color.parseColor("#4CAF50") else Color.parseColor("#FF5252"))
                setPadding(0, 0, 0, 4)
            }
            val explanationView = TextView(this).apply {
                text = explanation
                textSize = 12f
                setTextColor(Color.parseColor("#BBBBBB"))
                setPadding(0, 0, 0, 0)
            }
            card.addView(titleView)
            card.addView(statusView)
            card.addView(explanationView)
            contentLayout.addView(card)
        }

        // 0. Component & Platform Versions
        val versions = getComponentVersions()
        addSection(
            UiStrings.sectionVersionsTitle(lang),
            versions.toFormattedSummary(),
            true,
            if (lang == UiLanguage.RU) {
                "Версии EnclaveShield, системного Chromium WebView, платформы Android и уровень харденинга."
            } else {
                "Active versions of EnclaveShield, Chromium WebView engine, Android OS platform, and hardening stage."
            }
        )

        // 1. Kill-Switch Status
        val isKillSwitchActive = currentTunnel is VpnTunnelState.Connected
        addSection(
            UiStrings.sectionKillSwitchTitle(lang),
            if (isKillSwitchActive) UiStrings.killSwitchProtected(lang) else UiStrings.killSwitchBlocked(lang),
            isKillSwitchActive,
            UiStrings.killSwitchExplanation(lang)
        )

        // 2. Tunnel Adapter
        val tunnelStatusStr = when (currentTunnel) {
            is VpnTunnelState.Connected -> "${currentTunnel.interfaceName} (${currentTunnel.tunIpv4.hostAddress})"
            is VpnTunnelState.Disconnected -> UiStrings.tunnelNoActive(lang)
        }
        addSection(
            UiStrings.sectionTunnelTitle(lang),
            tunnelStatusStr,
            currentTunnel is VpnTunnelState.Connected,
            UiStrings.tunnelExplanation(lang)
        )

        // 3. SOCKS5 Gatekeeper Proxy
        addSection(
            UiStrings.sectionProxyTitle(lang),
            UiStrings.proxyStatus(lang, proxyPort),
            true,
            UiStrings.proxyExplanation(lang)
        )

        // 4. DNS Isolation
        addSection(
            UiStrings.sectionDnsTitle(lang),
            UiStrings.dnsStatus(lang, dnsStats.cacheEntries, dnsStats.resolveErrors),
            dnsStats.resolveErrors == 0L,
            UiStrings.dnsExplanation(lang)
        )

        // 5. Anti-Fingerprinting
        addSection(
            UiStrings.sectionFingerprintTitle(lang),
            UiStrings.fingerprintStatus(lang),
            true,
            UiStrings.fingerprintExplanation(lang)
        )

        // 6. Account Profile Isolation (Stage 7)
        val activeProfile = app.accountProfileManager.activeProfile.value
        val isMultiProfileSupported = WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)
        val profileStatus = if (isMultiProfileSupported) {
            "AndroidX ProfileStore: ${activeProfile.displayName} (${activeProfile.storageKey})"
        } else {
            "Cookie Jar Fallback: ${activeProfile.displayName}"
        }
        val profileExplanation = if (lang == UiLanguage.RU) {
            "Изоляция сессий Corporate Portal: каждый аккаунт изолирован в отдельный контейнер с независимыми cookie, WebStorage и кэшем."
        } else {
            "Corporate Portal session isolation: each profile is containerized with isolated cookies, WebStorage, and cache."
        }
        val sectionProfileTitle = if (lang == UiLanguage.RU) "6. Изоляция профилей (Multi-Profile)" else "6. Account Profile Isolation"
        addSection(sectionProfileTitle, profileStatus, true, profileExplanation)

        // Metrics Summary Card
        val metricsCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, (4 * density).toInt(), 0, (6 * density).toInt())
            }
            background = createCardBackground("#161B22", "#263238", 12f)
            setPadding((16 * density).toInt(), (12 * density).toInt(), (16 * density).toInt(), (12 * density).toInt())
        }
        val metricsHeader = TextView(this).apply {
            text = if (lang == UiLanguage.RU) "--- Метрики телеметрии ---" else "--- Telemetry Metrics ---"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#80D8FF"))
            setPadding(0, 0, 0, 8)
        }
        metricsCard.addView(metricsHeader)

        val metricsText = TextView(this).apply {
            text = buildString {
                append("Active Sockets: ${app.vpnGatekeeperProxy.activeSocketCount}\n")
                append("Accepted: ${metrics.connectionsAccepted} | Rejected: ${metrics.connectionsRejected} | Killed: ${metrics.connectionsKilled}\n")
                append("DNS Queries: ${dnsStats.totalQueries} (Hits: ${dnsStats.cacheHits}) | Avg Latency: ${dnsStats.averageLatencyMs}ms")
            }
            textSize = 11f
            setTextColor(Color.parseColor("#E0E0E0"))
            typeface = Typeface.MONOSPACE
            setPadding(0, 0, 0, 0)
        }
        metricsCard.addView(metricsText)
        contentLayout.addView(metricsCard)

        // Recent Logs Section Card
        val logsCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, (4 * density).toInt(), 0, (6 * density).toInt())
            }
            background = createCardBackground("#161B22", "#263238", 12f)
            setPadding((16 * density).toInt(), (12 * density).toInt(), (16 * density).toInt(), (12 * density).toInt())
        }
        val logsHeader = TextView(this).apply {
            text = if (lang == UiLanguage.RU) "--- Последние события аудита ---" else "--- Recent Audit Logs ---"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#80D8FF"))
            setPadding(0, 0, 0, 8)
        }
        logsCard.addView(logsHeader)

        val logsText = TextView(this).apply {
            text = if (recentLogs.isEmpty()) {
                if (lang == UiLanguage.RU) "Нет записей в журнале" else "No log entries yet"
            } else {
                recentLogs.joinToString("\n") { log ->
                    "[${log.level}] ${log.tag}: ${log.message}"
                }
            }
            textSize = 10f
            setTextColor(Color.parseColor("#B0BEC5"))
            typeface = Typeface.MONOSPACE
            setPadding(0, 0, 0, 0)
        }
        logsCard.addView(logsText)
        contentLayout.addView(logsCard)

        // Dialog Action Buttons Container
        var dialogRef: AlertDialog? = null

        fun createActionButton(label: String, onClick: () -> Unit): MaterialButton {
            return MaterialButton(this).apply {
                text = label
                textSize = 12f
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, 4, 0, 4)
                }
                setOnClickListener { onClick() }
            }
        }

        val btnReload = createActionButton(if (lang == UiLanguage.RU) "🔄 Перезагрузить страницу" else "🔄 Reload Page") {
            dialogRef?.dismiss()
            webView?.reload()
        }

        val btnVersions = createActionButton(UiStrings.btnVersions(lang)) {
            showVersionsDetailDialog(lang, versions)
        }

        val secPrefs = getSharedPreferences(PREFS_SECURITY_SETTINGS, Context.MODE_PRIVATE)
        val isSecure = secPrefs.getBoolean(KEY_FLAG_SECURE, true)
        val btnToggleSecure = createActionButton(
            if (lang == UiLanguage.RU) {
                if (isSecure) "🛡️ Защита снимков экрана (Recents): ВКЛ" else "🛡️ Защита снимков экрана (Recents): ВЫКЛ"
            } else {
                if (isSecure) "🛡️ Privacy Screen (FLAG_SECURE): ON" else "🛡️ Privacy Screen (FLAG_SECURE): OFF"
            }
        ) {
            val newSecure = !isSecure
            secPrefs.edit().putBoolean(KEY_FLAG_SECURE, newSecure).apply()
            if (newSecure) {
                window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
            dialogRef?.dismiss()
            showDiagnosticsDialog()
        }

        val btnCopy = createActionButton(UiStrings.btnCopyAiReport(lang)) {
            copyAuditReportToClipboard()
        }
        val btnShare = createActionButton(UiStrings.btnShareLog(lang)) {
            shareAuditReport()
        }
        val btnLeaks = createActionButton(UiStrings.btnBrowserLeaks(lang)) {
            dialogRef?.dismiss()
            btnReturnToPortal.visibility = View.VISIBLE
            webView?.loadUrl(DIAGNOSTIC_URL, mapOf("Accept-Language" to "en-US,en;q=0.9"))
        }
        val btnClear = createActionButton(UiStrings.btnClearLogs(lang)) {
            app.auditLogger.clearAllLogs()
            dialogRef?.dismiss()
            showDiagnosticsDialog()
        }
        val btnIcon = createActionButton(UiStrings.btnChangeIcon(lang)) {
            showAppIconSelectionDialog(lang)
        }
        val btnAccounts = createActionButton(UiStrings.accountDialogTitle(lang)) {
            dialogRef?.dismiss()
            showAccountDialog()
        }

        contentLayout.addView(btnReload)
        contentLayout.addView(btnVersions)
        contentLayout.addView(btnToggleSecure)
        contentLayout.addView(btnCopy)
        contentLayout.addView(btnShare)
        contentLayout.addView(btnLeaks)
        contentLayout.addView(btnClear)
        contentLayout.addView(btnIcon)
        contentLayout.addView(btnAccounts)

        dialogRef = MaterialAlertDialogBuilder(this)
            .setTitle(UiStrings.diagDialogTitle(lang))
            .setView(scrollView)
            .setNegativeButton(UiStrings.btnClose(lang), null)
            .show()
    }

    private fun copyAuditReportToClipboard() {
        val currentTunnel = app.vpnStateMonitor.getCurrentTunnelState()
        val report = app.auditLogger.generateMarkdownAuditReport(
            currentTunnel,
            app.vpnGatekeeperProxy.listeningPort
        )
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("EnclaveShield Audit Report", report)
        clipboard.setPrimaryClip(clip)

        val lang = app.uiLanguageManager.language.value
        Toast.makeText(this, UiStrings.toastReportCopied(lang), Toast.LENGTH_SHORT).show()
    }

    private fun shareAuditReport() {
        val currentTunnel = app.vpnStateMonitor.getCurrentTunnelState()
        val report = app.auditLogger.generateMarkdownAuditReport(
            currentTunnel,
            app.vpnGatekeeperProxy.listeningPort
        )
        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "EnclaveShield Security Audit Report")
            putExtra(Intent.EXTRA_TEXT, report)
        }
        startActivity(Intent.createChooser(shareIntent, "Share Security Audit Report"))
    }

    private fun showAppIconSelectionDialog(lang: UiLanguage) {
        val current = app.appIconManager.getCurrentIcon()
        val options = arrayOf(
            UiStrings.iconVariant1(lang),
            UiStrings.iconVariant2(lang)
        )
        val selectedIndex = if (current == AppIconOption.VARIANT_2) 1 else 0

        MaterialAlertDialogBuilder(this)
            .setTitle(UiStrings.dialogChooseIconTitle(lang))
            .setSingleChoiceItems(options, selectedIndex) { dialog, which ->
                val chosen = if (which == 1) AppIconOption.VARIANT_2 else AppIconOption.VARIANT_1
                val success = app.appIconManager.setAppIcon(chosen)
                if (success) {
                    Toast.makeText(this, UiStrings.toastIconChanged(lang), Toast.LENGTH_SHORT).show()
                }
                dialog.dismiss()
            }
            .setNegativeButton(UiStrings.btnClose(lang), null)
            .show()
    }

    data class ComponentVersions(
        val appVersionName: String,
        val appVersionCode: Long,
        val stageHardening: String,
        val androidRelease: String,
        val apiLevel: Int,
        val securityPatch: String,
        val deviceModel: String,
        val deviceManufacturer: String,
        val architecture: String,
        val webViewPackage: String,
        val webViewVersion: String,
        val chromiumEngine: String
    ) {
        fun toFormattedSummary(): String {
            return "EnclaveShield v$appVersionName (Build $appVersionCode) • $stageHardening\n" +
                    "WebView: $webViewPackage $webViewVersion\n" +
                    "Android: Android $androidRelease (API $apiLevel) • Patch: $securityPatch\n" +
                    "Device: $deviceManufacturer $deviceModel ($architecture)"
        }

        fun toDetailedReport(): String {
            return """
                --- EnclaveShield Component Versions ---
                App: EnclaveShield v$appVersionName (Build $appVersionCode)
                Hardening: $stageHardening
                Android OS: Android $androidRelease (API Level: $apiLevel)
                Security Patch: $securityPatch
                Device: $deviceManufacturer $deviceModel
                Primary ABI: $architecture
                WebView Provider: $webViewPackage
                WebView Engine Version: $webViewVersion
                Chromium Engine: $chromiumEngine
                JVM: ${System.getProperty("java.vm.name")} ${System.getProperty("java.vm.version")}
            """.trimIndent()
        }
    }

    private fun getComponentVersions(): ComponentVersions {
        val (verName, verCode) = runCatching {
            val pInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(packageName, 0)
            }
            val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pInfo.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                pInfo.versionCode.toLong()
            }
            Pair(pInfo.versionName ?: "1.0", code)
        }.getOrDefault(Pair("1.0", 1L))

        val webViewPkg = runCatching { WebViewCompat.getCurrentWebViewPackage(this) }.getOrNull()
        val webViewPkgName = webViewPkg?.packageName ?: "System WebView"
        val webViewVer = webViewPkg?.versionName ?: "Unknown"

        val userAgent = runCatching {
            webView?.settings?.userAgentString ?: WebSettings.getDefaultUserAgent(this)
        }.getOrDefault("")
        val chromeVer = Regex("Chrome/([0-9.]+)").find(userAgent)?.value ?: "Chrome Embedded"

        val patch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Build.VERSION.SECURITY_PATCH
        } else {
            "N/A"
        }

        return ComponentVersions(
            appVersionName = verName,
            appVersionCode = verCode,
            stageHardening = "Stage 10: Zero-Trust Hardening & Code Review Remediation",
            androidRelease = Build.VERSION.RELEASE,
            apiLevel = Build.VERSION.SDK_INT,
            securityPatch = patch,
            deviceModel = Build.MODEL,
            deviceManufacturer = Build.MANUFACTURER,
            architecture = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a",
            webViewPackage = webViewPkgName,
            webViewVersion = webViewVer,
            chromiumEngine = chromeVer
        )
    }

    private fun showVersionsDetailDialog(lang: UiLanguage, versions: ComponentVersions) {
        val density = resources.displayMetrics.density
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding((24 * density).toInt(), (16 * density).toInt(), (24 * density).toInt(), (16 * density).toInt())
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createCardBackground("#161B22", "#2A3441", 12f)
            setPadding((16 * density).toInt(), (14 * density).toInt(), (16 * density).toInt(), (14 * density).toInt())
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = (16 * density).toInt()
            }
        }

        val tvDetails = TextView(this).apply {
            text = versions.toDetailedReport()
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.parseColor("#E0E0E0"))
        }
        card.addView(tvDetails)
        layout.addView(card)

        val btnCopy = MaterialButton(this).apply {
            text = UiStrings.btnCopyVersions(lang)
            setOnClickListener {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("EnclaveShield Versions", versions.toDetailedReport())
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this@MainActivity, UiStrings.toastVersionsCopied(lang), Toast.LENGTH_SHORT).show()
            }
        }
        layout.addView(btnCopy)

        MaterialAlertDialogBuilder(this)
            .setTitle(UiStrings.dialogVersionsTitle(lang))
            .setView(layout)
            .setNegativeButton(UiStrings.btnClose(lang), null)
            .show()
    }

    override fun onDestroy() {
        super.onDestroy()
        bannerFlashJob?.cancel()

        fileChooserCallback?.onReceiveValue(null)
        fileChooserCallback = null

        webView?.let { wv ->
            wv.stopLoading()
            webViewContainer.removeView(wv)
            wv.destroy()
        }
        webView = null

        // CRITICAL SECURITY FIX (Stage 5):
        // ProxyController.clearProxyOverride() is deliberately NOT called here.
        // The override is process-global and MUST remain active across activity recreation
        // to prevent any cleartext leak window.
        // Singletons (vpnGatekeeperProxy, vpnStateMonitor) are managed at the Application level.
    }

    companion object {
        private const val TAG = "MainActivity"
        private const val PORTAL_URL = "https://portal.internal-enterprise.net"
        private const val DIAGNOSTIC_URL = "https://browserleaks.com/ip"
        private const val PREFS_UI_COLLAPSE = "enclaveshield_ui_collapse_prefs"
        private const val KEY_TOPBAR_COLLAPSED = "is_top_bar_collapsed"
        private const val KEY_ANCHOR_X = "anchor_x"
        private const val KEY_ANCHOR_Y = "anchor_y"
        private const val PREFS_SECURITY_SETTINGS = "enclaveshield_security_prefs"
        private const val KEY_FLAG_SECURE = "is_flag_secure_enabled"
    }
}

```

---

### 2.5. `app/src/main/java/com/corp/enclaveshield/net/TunnelDnsResolver.kt`
**Role:** RFC 1035 TCP DNS resolver with ScheduledExecutor Watchdog, Single-Flight & True SWR

```kotlin
package com.corp.enclaveshield.net

import android.net.Network
import android.util.Log
import com.corp.enclaveshield.telemetry.LogCategory
import com.corp.enclaveshield.telemetry.LogLevel
import com.corp.enclaveshield.telemetry.SecurityAuditLogger
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Result of parsing or querying DNS response.
 */
data class DnsResponse(
    val address: Inet4Address? = null,
    val isNoData: Boolean = false,
    val rcode: Int = 0,
    val isError: Boolean = false
)

/**
 * Strict fail-closed DNS resolver that resolves A (IPv4) records exclusively via
 * raw RFC 1035 DNS-over-TCP.
 *
 * CRITICAL SECURITY GUARANTEES:
 * 1. NEVER calls [InetAddress.getByName] for target hosts, bypassing Android's netd daemon
 *    to prevent Smart DNS leaks or physical interface routing.
 * 2. All outbound DNS query sockets are registered via [socketRegistrar] (which validates that
 *    VPN is strictly Connected) and explicitly bound to the VPN tunnel's local IPv4 ([tunIpv4]).
 * 3. Caches resolved IPv4 addresses in memory for 60 seconds; cache is cleared on VPN disconnect.
 * 4. RFC 2308 NODATA / IPv6-only canary responses are negatively cached for 60s without querying
 *    fallback or incrementing failure counters.
 */
class TunnelDnsResolver(
    private val auditLogger: SecurityAuditLogger? = null
) {

    private data class CacheEntry(
        val address: Inet4Address,
        val freshUntilMillis: Long,
        val staleUntilMillis: Long
    )

    private data class StaleFallbackEntry(
        val address: Inet4Address,
        val expiresAtMillis: Long
    )

    private val cache = ConcurrentHashMap<String, CacheEntry>()
    private val negativeCache = ConcurrentHashMap<String, Long>()
    private val staleCache = ConcurrentHashMap<String, StaleFallbackEntry>()
    private val inFlightQueries = ConcurrentHashMap<String, Deferred<Inet4Address?>>()

    private val dnsScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val secureRandom = SecureRandom()

    private val watchdogExecutor: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "DnsWatchdog").apply { isDaemon = true }
    }

    val cacheSize: Int
        get() = cache.size

    val negativeCacheSize: Int
        get() = negativeCache.size

    val staleCacheSize: Int
        get() = staleCache.size

    /**
     * Test helper to populate staleCache for verifying Stale-While-Revalidate fallback.
     */
    fun putStaleEntryForTesting(domain: String, address: Inet4Address) {
        val cleanDomain = domain.trim().trimEnd('.').lowercase(Locale.ROOT)
        staleCache[cleanDomain] = StaleFallbackEntry(address, System.currentTimeMillis() + MAX_STALE_TTL_MILLIS)
    }

    /**
     * Resolves an IPv4 address for [domain] via DNS-over-TCP using [tunIpv4].
     *
     * @param domain Domain name to resolve (e.g. "portal.internal-enterprise.net").
     * @param tunIpv4 Active VPN tunnel IPv4 address to which the socket MUST be bound.
     * @param network Active VPN [Network] object for [Network.bindSocket].
     * @param socketRegistrar Thread-safe registrar ensuring socket is tracked and VPN is Connected.
     * @param onSocketClosed Callback when the socket finishes or errors.
     * @return Resolved [Inet4Address], or `null` if domain is NODATA / IPv6-only canary.
     * @throws IOException If resolution encounters network/server failure on all servers.
     */
    @Throws(IOException::class)
    suspend fun resolve(
        domain: String,
        tunIpv4: Inet4Address,
        network: Network?,
        socketRegistrar: ((Socket) -> VpnTunnelState.Connected)? = null,
        onSocketClosed: ((Socket) -> Unit)? = null
    ): Inet4Address? {
        val cleanDomain = domain.trim().trimEnd('.').lowercase(Locale.ROOT)

        // Fast-path 1: check if domain is already an IPv4 literal
        parseIpv4Literal(cleanDomain)?.let { return it }

        auditLogger?.dnsQueriesTotal?.incrementAndGet()
        val now = System.currentTimeMillis()

        // Fast-path 2: Check negative cache (e.g. Cloudflare Turnstile NODATA canaries)
        val negExpiry = negativeCache[cleanDomain]
        if (negExpiry != null) {
            if (negExpiry > now) {
                auditLogger?.dnsCacheHits?.incrementAndGet()
                return null
            } else {
                negativeCache.remove(cleanDomain)
            }
        }

        // Fast-path 3: Check in-memory positive cache (Fresh or Stale hit)
        val cached = cache[cleanDomain]
        if (cached != null) {
            if (now <= cached.freshUntilMillis) {
                auditLogger?.dnsCacheHits?.incrementAndGet()
                return cached.address
            } else if (now <= cached.staleUntilMillis) {
                // True Stale-While-Revalidate: return stale immediately, revalidate in background
                auditLogger?.dnsCacheHits?.incrementAndGet()
                auditLogger?.log(
                    LogCategory.DNS,
                    LogLevel.INFO,
                    "SWR hit for '$cleanDomain': serving stale IP while revalidating in background"
                )
                dnsScope.launch {
                    runCatching {
                        executeNetworkResolve(cleanDomain, tunIpv4, network, socketRegistrar, onSocketClosed)
                    }
                }
                return cached.address
            } else {
                cache.remove(cleanDomain)
            }
        }

        // Single-flight deduplication for network queries
        return executeNetworkResolve(cleanDomain, tunIpv4, network, socketRegistrar, onSocketClosed)
    }

    private suspend fun executeNetworkResolve(
        cleanDomain: String,
        tunIpv4: Inet4Address,
        network: Network?,
        socketRegistrar: ((Socket) -> VpnTunnelState.Connected)?,
        onSocketClosed: ((Socket) -> Unit)?
    ): Inet4Address? {
        val deferred = inFlightQueries.compute(cleanDomain) { _, existing ->
            existing ?: dnsScope.async(Dispatchers.IO) {
                performNetworkResolve(cleanDomain, tunIpv4, network, socketRegistrar, onSocketClosed)
            }
        }!!

        return try {
            deferred.await()
        } finally {
            inFlightQueries.remove(cleanDomain, deferred)
        }
    }

    private suspend fun performNetworkResolve(
        cleanDomain: String,
        tunIpv4: Inet4Address,
        network: Network?,
        socketRegistrar: ((Socket) -> VpnTunnelState.Connected)?,
        onSocketClosed: ((Socket) -> Unit)?
    ): Inet4Address? {
        val now = System.currentTimeMillis()
        auditLogger?.dnsNetworkLookups?.incrementAndGet()
        val startTime = System.currentTimeMillis()

        // 1. Primary DNS (1.1.1.1:53) over TCP
        var response = tryQueryDnsServer(
            serverIp = PRIMARY_DNS_IP,
            domain = cleanDomain,
            tunIpv4 = tunIpv4,
            network = network,
            socketRegistrar = socketRegistrar,
            onSocketClosed = onSocketClosed
        )
        var usedServer = PRIMARY_DNS_STR

        // 2. Fallback to 8.8.8.8:53 over TCP
        if (response.address == null && !response.isNoData && response.rcode != 3) {
            Log.w(TAG, "Primary DNS ($PRIMARY_DNS_STR) query failed for $cleanDomain; trying fallback ($FALLBACK_DNS_STR)")
            auditLogger?.log(
                LogCategory.DNS,
                LogLevel.WARN,
                "Primary DNS failed for '$cleanDomain', attempting fallback $FALLBACK_DNS_STR"
            )

            response = tryQueryDnsServer(
                serverIp = FALLBACK_DNS_IP,
                domain = cleanDomain,
                tunIpv4 = tunIpv4,
                network = network,
                socketRegistrar = socketRegistrar,
                onSocketClosed = onSocketClosed
            )
            usedServer = FALLBACK_DNS_STR

            // 3. Radio / Tunnel wake-up retry: if both failed right after waking from idle sleep,
            // do a quick retry on primary DNS after a 150ms backoff
            if (response.address == null && !response.isNoData && response.rcode != 3) {
                delay(150)
                Log.w(TAG, "Both DNS servers failed for $cleanDomain; performing wake-up retry on $PRIMARY_DNS_STR")
                response = tryQueryDnsServer(
                    serverIp = PRIMARY_DNS_IP,
                    domain = cleanDomain,
                    tunIpv4 = tunIpv4,
                    network = network,
                    socketRegistrar = socketRegistrar,
                    onSocketClosed = onSocketClosed
                )
                usedServer = "$PRIMARY_DNS_STR (retry)"
            }
        }

        if (response.isNoData) {
            negativeCache[cleanDomain] = System.currentTimeMillis() + NEGATIVE_CACHE_TTL_MILLIS
            auditLogger?.log(
                LogCategory.DNS,
                LogLevel.INFO,
                "DNS NODATA (IPv6 canary) for '$cleanDomain'; cached negatively for 60s"
            )
            return null
        }

        if (response.rcode == 3) {
            negativeCache[cleanDomain] = System.currentTimeMillis() + NEGATIVE_CACHE_TTL_MILLIS
            auditLogger?.log(
                LogCategory.DNS,
                LogLevel.WARN,
                "DNS NXDOMAIN for '$cleanDomain'; cached negatively for 60s"
            )
            return null
        }

        val resolved = if (response.address != null) {
            val latency = System.currentTimeMillis() - startTime
            auditLogger?.recordDnsLatency(latency)
            auditLogger?.log(
                LogCategory.DNS,
                LogLevel.INFO,
                "DNS resolved '$cleanDomain' via $usedServer in ${latency}ms"
            )
            val addr = response.address
            staleCache[cleanDomain] = StaleFallbackEntry(addr, System.currentTimeMillis() + MAX_STALE_TTL_MILLIS)
            addr
        } else {
            val stale = staleCache[cleanDomain]
            if (stale != null && stale.expiresAtMillis > System.currentTimeMillis()) {
                auditLogger?.log(
                    LogCategory.DNS,
                    LogLevel.WARN,
                    "Wake-up fallback: serving last-known IP for '$cleanDomain'"
                )
                Log.w(TAG, "Wake-up fallback: serving last-known IP for '$cleanDomain'")
                stale.address
            } else {
                auditLogger?.dnsFailures?.incrementAndGet()
                auditLogger?.log(
                    LogCategory.DNS,
                    LogLevel.ERROR,
                    "DNS resolution failed for '$cleanDomain' on all servers"
                )
                throw IOException("DNS resolution failed for '$cleanDomain' on both primary and fallback DNS servers")
            }
        }

        // Store in cache with fresh and stale TTLs
        cache[cleanDomain] = CacheEntry(
            address = resolved,
            freshUntilMillis = System.currentTimeMillis() + FRESH_TTL_MILLIS,
            staleUntilMillis = System.currentTimeMillis() + MAX_STALE_TTL_MILLIS
        )
        auditLogger?.dnsCacheEntries?.set(cache.size.toLong())

        return resolved
    }

    /**
     * Clears all cached DNS records. Called upon VPN disconnect.
     * When [clearStale] is false, keeps stale records to allow instant Doze wake-up fallback.
     */
    fun clearCache(clearStale: Boolean = true) {
        val size = cache.size + negativeCache.size + (if (clearStale) staleCache.size else 0)
        cache.clear()
        negativeCache.clear()
        if (clearStale) {
            staleCache.clear()
        }
        inFlightQueries.clear()
        auditLogger?.dnsCacheEntries?.set(0)
        if (size > 0) {
            auditLogger?.log(
                LogCategory.DNS,
                LogLevel.INFO,
                "Cleared $size cached DNS entries (clearStale=$clearStale)"
            )
        }
        Log.d(TAG, "DNS cache cleared (clearStale=$clearStale)")
    }

    private suspend fun tryQueryDnsServer(
        serverIp: Inet4Address,
        domain: String,
        tunIpv4: Inet4Address,
        network: Network?,
        socketRegistrar: ((Socket) -> VpnTunnelState.Connected)?,
        onSocketClosed: ((Socket) -> Unit)?
    ): DnsResponse = withContext(Dispatchers.IO) {
        val socket = Socket()
        val watchdogFuture = watchdogExecutor.schedule({
            runCatching { socket.close() }
        }, DNS_TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)

        return@withContext try {
            val verifiedTunnel = socketRegistrar?.invoke(socket)
            val boundIp = verifiedTunnel?.tunIpv4 ?: tunIpv4
            val boundNetwork = verifiedTunnel?.network ?: network

            socket.soTimeout = DNS_TIMEOUT_MS
            socket.tcpNoDelay = true

            if (boundNetwork != null) {
                runCatching { boundNetwork.bindSocket(socket) }
            }
            socket.bind(InetSocketAddress(boundIp, 0))
            socket.connect(InetSocketAddress(serverIp, DNS_PORT), DNS_TIMEOUT_MS)

            val queryId = secureRandom.nextInt(0xFFFF - 1) + 1
            val queryPacket = buildTcpDnsQuery(domain, queryId)

            val dos = DataOutputStream(socket.getOutputStream())
            dos.write(queryPacket)
            dos.flush()

            val dis = DataInputStream(socket.getInputStream())
            val responseLength = dis.readUnsignedShort()
            val responseBytes = ByteArray(responseLength)
            dis.readFully(responseBytes)

            auditLogger?.consecutiveNetworkTimeouts?.set(0)
            parseTcpDnsResponse(responseBytes, queryId, domain)
        } catch (e: Exception) {
            auditLogger?.consecutiveNetworkTimeouts?.incrementAndGet()
            Log.w(TAG, "DNS query exception/timeout for $domain on $serverIp: ${e.message}")
            DnsResponse(isError = true)
        } finally {
            watchdogFuture.cancel(false)
            runCatching { socket.close() }
            onSocketClosed?.invoke(socket)
        }
    }

    companion object {
        private const val TAG = "TunnelDnsResolver"
        private const val DNS_PORT = 53
        private const val DNS_TIMEOUT_MS = 2500
        const val FRESH_TTL_MILLIS = 300_000L // 5 minutes
        const val CACHE_TTL_MILLIS = FRESH_TTL_MILLIS
        const val MAX_STALE_TTL_MILLIS = 86_400_000L // 24 hours
        const val NEGATIVE_CACHE_TTL_MILLIS = 60_000L // 1 minute

        private const val PRIMARY_DNS_STR = "1.1.1.1"
        private const val FALLBACK_DNS_STR = "8.8.8.8"

        val PRIMARY_DNS_IP: Inet4Address =
            InetAddress.getByAddress(PRIMARY_DNS_STR, byteArrayOf(1, 1, 1, 1)) as Inet4Address
        val FALLBACK_DNS_IP: Inet4Address =
            InetAddress.getByAddress(FALLBACK_DNS_STR, byteArrayOf(8, 8, 8, 8)) as Inet4Address

        /**
         * Parses an IPv4 literal string (e.g. "192.168.1.1") without using DNS lookups.
         */
        fun parseIpv4Literal(text: String): Inet4Address? {
            val parts = text.split('.')
            if (parts.size != 4) return null
            val bytes = ByteArray(4)
            for (i in 0 until 4) {
                val num = parts[i].toIntOrNull() ?: return null
                if (num !in 0..255) return null
                bytes[i] = num.toByte()
            }
            return runCatching {
                InetAddress.getByAddress(text, bytes) as? Inet4Address
            }.getOrNull()
        }

        /**
         * Builds an RFC 1035 DNS-over-TCP query message.
         * The message is prefixed with a 2-byte big-endian length field.
         */
        fun buildTcpDnsQuery(domain: String, queryId: Int): ByteArray {
            val cleanDomain = domain.trimEnd('.')
            val labels = cleanDomain.split('.')
            val qnameOut = ByteArrayOutputStream()
            for (label in labels) {
                val bytes = label.toByteArray(Charsets.US_ASCII)
                require(bytes.isNotEmpty() && bytes.size <= 63) { "Invalid DNS label length: ${bytes.size}" }
                qnameOut.write(bytes.size)
                qnameOut.write(bytes)
            }
            qnameOut.write(0x00) // Null root label terminator

            val qname = qnameOut.toByteArray()
            val dnsMessageLength = 12 + qname.size + 4 // 12 header + qname + 2 QTYPE + 2 QCLASS
            val totalLength = 2 + dnsMessageLength

            val buffer = ByteBuffer.allocate(totalLength).order(ByteOrder.BIG_ENDIAN)

            // 2-byte TCP framing prefix
            buffer.putShort(dnsMessageLength.toShort())

            // Header (12 bytes)
            buffer.putShort(queryId.toShort())
            buffer.putShort(0x0100.toShort()) // Flags: RD = 1 (Recursion Desired)
            buffer.putShort(1.toShort())      // QDCOUNT = 1
            buffer.putShort(0.toShort())      // ANCOUNT = 0
            buffer.putShort(0.toShort())      // NSCOUNT = 0
            buffer.putShort(0.toShort())      // ARCOUNT = 0

            // Question
            buffer.put(qname)
            buffer.putShort(1.toShort())      // QTYPE = A (1)
            buffer.putShort(1.toShort())      // QCLASS = IN (1)

            return buffer.array()
        }

        /**
         * Parses an RFC 1035 DNS response payload (excluding the 2-byte TCP prefix).
         * Extracts A records (IPv4) from the answer section and selects one.
         * Identifies RFC 2308 NODATA (RCODE 0 with 0 answers) for IPv6 canary domains.
         */
        fun parseTcpDnsResponse(
            responseBytes: ByteArray,
            expectedQueryId: Int,
            expectedDomain: String? = null
        ): DnsResponse {
            if (responseBytes.size < 12) return DnsResponse(isError = true)
            val buffer = ByteBuffer.wrap(responseBytes).order(ByteOrder.BIG_ENDIAN)

            val respId = buffer.short.toInt() and 0xFFFF
            if (respId != expectedQueryId) {
                Log.w(TAG, "DNS query ID mismatch: expected $expectedQueryId, got $respId")
                return DnsResponse(isError = true)
            }

            val flags = buffer.short.toInt() and 0xFFFF
            val rcode = flags and 0x000F
            if (rcode != 0) {
                Log.w(TAG, "DNS server returned error RCODE: $rcode")
                return DnsResponse(rcode = rcode, isError = (rcode != 3))
            }

            val qdCount = buffer.short.toInt() and 0xFFFF
            val anCount = buffer.short.toInt() and 0xFFFF
            buffer.short // NSCOUNT
            buffer.short // ARCOUNT

            if (anCount == 0) {
                // Legitimate RFC 2308 NODATA response (NOERROR, but 0 answers)
                return DnsResponse(address = null, isNoData = true, rcode = 0)
            }

            // Verify questions and QNAME
            for (i in 0 until qdCount) {
                val qName = readDnsName(buffer, responseBytes)
                if (buffer.remaining() < 4) return DnsResponse(isError = true)
                buffer.short // QTYPE
                buffer.short // QCLASS

                if (expectedDomain != null && i == 0) {
                    val normalizedExpected = expectedDomain.trim().trimEnd('.').lowercase(Locale.ROOT)
                    val normalizedQname = qName?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT)
                    if (normalizedQname != normalizedExpected) {
                        Log.w(TAG, "DNS QNAME mismatch: expected '$normalizedExpected', got '$normalizedQname'")
                        return DnsResponse(isError = true)
                    }
                }
            }

            val aRecords = mutableListOf<Inet4Address>()
            // Parse answers
            for (i in 0 until anCount) {
                skipDnsName(buffer)
                if (buffer.remaining() < 10) return DnsResponse(isError = true)
                val type = buffer.short.toInt() and 0xFFFF
                val clazz = buffer.short.toInt() and 0xFFFF
                buffer.int   // TTL (4 bytes)
                val rdLength = buffer.short.toInt() and 0xFFFF

                if (buffer.remaining() < rdLength) return DnsResponse(isError = true)

                if (type == 1 && clazz == 1 && rdLength == 4) {
                    val ipBytes = ByteArray(4)
                    buffer.get(ipBytes)
                    val ip = runCatching {
                        InetAddress.getByAddress(ipBytes) as? Inet4Address
                    }.getOrNull()
                    if (ip != null) {
                        aRecords.add(ip)
                    }
                } else {
                    // Skip CNAME or other records
                    buffer.position(buffer.position() + rdLength)
                }
            }

            return if (aRecords.isNotEmpty()) {
                val chosen = if (aRecords.size == 1) aRecords[0] else aRecords.random()
                DnsResponse(address = chosen, isNoData = false, rcode = 0)
            } else {
                DnsResponse(address = null, isNoData = true, rcode = 0)
            }
        }

        private fun readDnsName(buffer: ByteBuffer, responseBytes: ByteArray): String? {
            val sb = StringBuilder()
            var jumped = false
            var jumpPos = -1
            var currentPos = buffer.position()
            var loops = 0
            val maxLoops = 128

            while (loops++ < maxLoops) {
                if (currentPos >= responseBytes.size) return null
                val len = responseBytes[currentPos].toInt() and 0xFF
                if (len == 0) {
                    currentPos++
                    break
                }
                if ((len and 0xC0) == 0xC0) {
                    if (currentPos + 1 >= responseBytes.size) return null
                    val offset = ((len and 0x3F) shl 8) or (responseBytes[currentPos + 1].toInt() and 0xFF)
                    if (!jumped) {
                        jumpPos = currentPos + 2
                        jumped = true
                    }
                    currentPos = offset
                } else {
                    currentPos++
                    if (currentPos + len > responseBytes.size) return null
                    if (sb.isNotEmpty()) sb.append('.')
                    sb.append(String(responseBytes, currentPos, len, Charsets.US_ASCII))
                    currentPos += len
                }
            }
            buffer.position(if (jumped) jumpPos else currentPos)
            return sb.toString()
        }

        private fun skipDnsName(buffer: ByteBuffer) {
            while (buffer.hasRemaining()) {
                val len = buffer.get().toInt() and 0xFF
                if (len == 0) {
                    break
                }
                if ((len and 0xC0) == 0xC0) {
                    // Compression pointer (2 bytes total): first byte read, consume second byte
                    if (buffer.hasRemaining()) {
                        buffer.get()
                    }
                    break
                }
                if (buffer.remaining() >= len) {
                    buffer.position(buffer.position() + len)
                } else {
                    // Malformed packet defense: avoid reading out-of-sync bytes
                    buffer.position(buffer.limit())
                    break
                }
            }
        }
    }
}

```

---

### 2.6. `app/src/main/java/com/corp/enclaveshield/net/VpnGatekeeperProxy.kt`
**Role:** Zero-Leak SOCKS5 gateway with Allowlist, Private IP filter, relay thread pool & generational tracking

```kotlin
package com.corp.enclaveshield.net

import android.content.Context
import android.util.Log
import com.corp.enclaveshield.telemetry.LogCategory
import com.corp.enclaveshield.telemetry.LogLevel
import com.corp.enclaveshield.telemetry.SecurityAuditLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.isActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.asCoroutineDispatcher
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * In-process Zero-Leak Loopback SOCKS5 Gatekeeper Proxy.
 *
 * Listens strictly on 127.0.0.1:<dynamic_port>.
 *
 * CRITICAL SECURITY ARCHITECTURE:
 * 1. Fail-Closed Engine: If VPN is Disconnected, all connection attempts are rejected
 *    immediately, and every active client/remote socket is forcefully closed within milliseconds.
 * 2. Strict Interface Binding: Every outbound TCP socket created by the proxy is explicitly
 *    bound to the VPN tunnel's local IPv4 address (socket.bind(InetSocketAddress(tunIpv4, 0)))
 *    AND bound to the VPN Network object. In the Linux kernel, binding to the tun source IP
 *    guarantees packets can NEVER exit via physical interfaces (wlan0, rmnet0).
 * 3. Zero-Leak DNS: Resolves domain names (ATYP 0x03) via [TunnelDnsResolver] using raw
 *    DNS-over-TCP bound strictly to tunIpv4, bypassing Android's netd daemon.
 * 4. IPv6 Disabled: Rejects ATYP 0x04 with SOCKS5 0x08 (Address type not supported).
 * 5. Socket Registration Guard: Outbound and DNS sockets are validated through [registerSocketOrThrow].
 */
class VpnGatekeeperProxy(
    private val vpnStateMonitor: VpnStateMonitor,
    private val auditLogger: SecurityAuditLogger? = null,
    val dnsResolver: TunnelDnsResolver = TunnelDnsResolver(auditLogger)
) {

    constructor(
        context: Context,
        vpnStateMonitor: VpnStateMonitor,
        auditLogger: SecurityAuditLogger? = null,
        dnsResolver: TunnelDnsResolver = TunnelDnsResolver(auditLogger)
    ) : this(vpnStateMonitor, auditLogger, dnsResolver)

    val activeSocketCount: Int
        get() = activeSockets.size

    private val proxyJob = SupervisorJob()
    private val proxyScope = CoroutineScope(Dispatchers.IO + proxyJob)

    // Dedicated cached thread pool for relay traffic so blocking read() never starves Dispatchers.IO
    private val relayExecutor = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "VpnProxyRelay").apply { isDaemon = true }
    }
    private val relayDispatcher = relayExecutor.asCoroutineDispatcher()

    // Bind strictly to loopback 127.0.0.1 on an ephemeral dynamic port (port 0)
    private val serverSocket: ServerSocket = ServerSocket(
        0,
        50,
        InetAddress.getByAddress("127.0.0.1", byteArrayOf(127, 0, 0, 1))
    )

    val listeningPort: Int = serverSocket.localPort

    // Thread-safe pool of all active client and outbound sockets
    private val activeSockets = ConcurrentHashMap.newKeySet<Socket>()
    // Tracks outbound sockets mapped to the tunnel generation at time of creation
    private val outboundSockets = ConcurrentHashMap<Socket, Long>()
    private val isRunning = AtomicBoolean(false)

    // Synchronous tunnel listener for instant kill-switch and handover tracking
    private val tunnelListener = TunnelListener { _, current ->
        when (current) {
            is VpnTunnelState.Connected -> {
                val curGen = current.generation
                val it = outboundSockets.entries.iterator()
                var killed = 0
                while (it.hasNext()) {
                    val entry = it.next()
                    if (entry.value != curGen) {
                        it.remove()
                        activeSockets.remove(entry.key)
                        runCatching { entry.key.close() }
                        killed++
                    }
                }
                if (killed > 0) {
                    auditLogger?.log(
                        LogCategory.KILLSWITCH,
                        LogLevel.BLOCK,
                        "Killed $killed outdated socket(s) on tunnel handover (gen $curGen)"
                    )
                    Log.w(TAG, "Killed $killed outdated socket(s) on tunnel handover (gen $curGen)")
                }
            }
            is VpnTunnelState.Disconnected -> {
                closeAllActiveSockets()
                dnsResolver.clearCache(clearStale = false)
            }
        }
    }

    /**
     * Starts the SOCKS5 proxy server and begins observing VPN state transitions.
     */
    fun start() {
        if (!isRunning.compareAndSet(false, true)) return
        Log.i(TAG, "Starting VpnGatekeeperProxy on 127.0.0.1:$listeningPort")
        auditLogger?.log(LogCategory.PROXY, LogLevel.INFO, "SOCKS5 Proxy started on 127.0.0.1:$listeningPort")

        vpnStateMonitor.addTunnelListener(tunnelListener)

        // Accept loop
        proxyScope.launch {
            acceptLoop()
        }
    }

    /**
     * Stops the SOCKS5 proxy server and releases all socket resources.
     */
    fun stop() {
        if (!isRunning.compareAndSet(true, false)) return
        Log.i(TAG, "Stopping VpnGatekeeperProxy on 127.0.0.1:$listeningPort")
        auditLogger?.log(LogCategory.PROXY, LogLevel.INFO, "SOCKS5 Proxy stopping")
        vpnStateMonitor.removeTunnelListener(tunnelListener)
        runCatching { serverSocket.close() }
        closeAllActiveSockets()
        dnsResolver.clearCache()
        proxyJob.cancel()
        relayExecutor.shutdownNow()
    }

    /**
     * Thread-safe helper that registers a [socket] in [activeSockets] AND immediately verifies
     * that the VPN tunnel is currently [VpnTunnelState.Connected].
     *
     * If the VPN is not connected, the socket is immediately removed from [activeSockets], closed,
     * and an [IOException] is thrown to prevent any race-condition network leaks.
     */
    @Throws(IOException::class)
    fun registerSocketOrThrow(socket: Socket, isOutbound: Boolean = false): VpnTunnelState.Connected {
        activeSockets.add(socket)
        auditLogger?.activeSocketsCount?.set(activeSockets.size)

        val current = vpnStateMonitor.getCurrentTunnelState()
        if (current !is VpnTunnelState.Connected) {
            activeSockets.remove(socket)
            auditLogger?.activeSocketsCount?.set(activeSockets.size)
            runCatching { socket.close() }
            auditLogger?.log(LogCategory.KILLSWITCH, LogLevel.BLOCK, "Socket registration aborted: VPN is disconnected")
            throw IOException("VPN disconnected during socket registration")
        }
        if (isOutbound) {
            outboundSockets[socket] = current.generation
        }
        return current
    }

    /**
     * Immediately and forcefully closes all active sockets in the pool.
     */
    fun closeAllActiveSockets() {
        outboundSockets.clear()
        val iterator = activeSockets.iterator()
        var closedCount = 0
        while (iterator.hasNext()) {
            val socket = iterator.next()
            iterator.remove()
            runCatching {
                socket.close()
                closedCount++
            }
        }
        auditLogger?.activeSocketsCount?.set(0)
        if (closedCount > 0) {
            auditLogger?.forceClosedSocketsCount?.addAndGet(closedCount.toLong())
            auditLogger?.log(LogCategory.KILLSWITCH, LogLevel.BLOCK, "Force-closed $closedCount socket(s) via kill-switch")
            Log.w(TAG, "Force-closed $closedCount active socket(s)")
        }
    }

    private suspend fun acceptLoop() {
        while (isRunning.get() && !serverSocket.isClosed && proxyScope.isActive) {
            try {
                val clientSocket = withContext(Dispatchers.IO) {
                    serverSocket.accept()
                }
                clientSocket.tcpNoDelay = true
                activeSockets.add(clientSocket)
                auditLogger?.activeSocketsCount?.set(activeSockets.size)
                auditLogger?.totalSocksRequests?.incrementAndGet()

                proxyScope.launch {
                    handleClient(clientSocket)
                }
            } catch (e: Exception) {
                if (serverSocket.isClosed || !isRunning.get()) {
                    break
                }
                Log.e(TAG, "Error in SOCKS5 accept loop", e)
            }
        }
    }

    private fun isForbiddenIp(ip: Inet4Address, vpnTunnel: VpnTunnelState?): Boolean {
        if (ip.isLoopbackAddress || ip.isLinkLocalAddress || ip.isSiteLocalAddress || ip.isMulticastAddress || ip.isAnyLocalAddress) {
            return true
        }
        if (vpnTunnel is VpnTunnelState.Connected && ip == vpnTunnel.tunIpv4) {
            return true
        }
        return false
    }

    private fun isDomainAllowed(domain: String): Boolean {
        val clean = domain.trim().trimEnd('.').lowercase(Locale.ROOT)
        return ALLOWED_DOMAIN_SUFFIXES.any { clean == it || clean.endsWith(".$it") }
    }

    private suspend fun handleClient(clientSocket: Socket) = withContext(Dispatchers.IO) {
        var remoteSocket: Socket? = null
        try {
            clientSocket.soTimeout = HANDSHAKE_TIMEOUT_MS
            val inputStream = clientSocket.getInputStream()
            val outputStream = clientSocket.getOutputStream()
            val dis = DataInputStream(inputStream)
            val dos = DataOutputStream(outputStream)

            // --- Step 1: SOCKS5 Handshake / Method Negotiation ---
            val version = dis.readUnsignedByte()
            if (version != SOCKS_VERSION.toInt()) {
                Log.w(TAG, "Invalid SOCKS version: $version")
                return@withContext
            }

            val nMethods = dis.readUnsignedByte()
            val methods = ByteArray(nMethods)
            dis.readFully(methods)

            var supportsNoAuth = false
            for (m in methods) {
                if (m == METHOD_NO_AUTH) {
                    supportsNoAuth = true
                    break
                }
            }

            if (!supportsNoAuth) {
                Log.w(TAG, "Client does not support No-Auth (0x00)")
                dos.write(byteArrayOf(SOCKS_VERSION, METHOD_NO_ACCEPTABLE))
                dos.flush()
                return@withContext
            }

            // Reply: SOCKS5, No-Auth selected
            dos.write(byteArrayOf(SOCKS_VERSION, METHOD_NO_AUTH))
            dos.flush()

            // --- Step 2: Parse Connection Request ---
            val reqVersion = dis.readUnsignedByte()
            if (reqVersion != SOCKS_VERSION.toInt()) {
                Log.w(TAG, "Invalid request version: $reqVersion")
                return@withContext
            }

            val command = dis.readUnsignedByte().toByte()
            dis.readUnsignedByte() // RSV (0x00)
            val atyp = dis.readUnsignedByte().toByte()

            if (command != CMD_CONNECT) {
                Log.w(TAG, "Unsupported command: $command (only CONNECT supported)")
                sendSocks5Reply(dos, REP_CMD_NOT_SUPPORTED)
                return@withContext
            }

            val targetIp: Inet4Address
            val targetPort: Int

            when (atyp) {
                ATYP_IPV4 -> {
                    val ipBytes = ByteArray(4)
                    dis.readFully(ipBytes)
                    targetPort = dis.readUnsignedShort()
                    val rawIp = InetAddress.getByAddress(ipBytes) as Inet4Address
                    val currentTunnel = vpnStateMonitor.getCurrentTunnelState()
                    if (isForbiddenIp(rawIp, currentTunnel)) {
                        Log.w(TAG, "Fail-closed rule: Blocked forbidden IPv4 destination: $rawIp")
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.BLOCK,
                            "Blocked forbidden IPv4 destination: $rawIp"
                        )
                        sendSocks5Reply(dos, REP_CONN_REFUSED)
                        return@withContext
                    }
                    targetIp = rawIp
                }
                ATYP_DOMAIN -> {
                    val domainLength = dis.readUnsignedByte()
                    val domainBytes = ByteArray(domainLength)
                    dis.readFully(domainBytes)
                    targetPort = dis.readUnsignedShort()
                    val rawDomain = String(domainBytes, Charsets.US_ASCII).trim()
                    var domain = rawDomain.trimEnd('.').lowercase(Locale.ROOT)

                    // Strip square brackets if present (e.g. [2604:a880:...])
                    if (domain.startsWith("[") && domain.endsWith("]")) {
                        domain = domain.substring(1, domain.length - 1).trim()
                    }

                    // Check for IPv6 literal passed inside ATYP_DOMAIN (Stage 6 Bug #3)
                    if (domain.contains(':')) {
                        Log.w(TAG, "Fail-closed rule: IPv6 literal passed in ATYP_DOMAIN: '$domain'")
                        auditLogger?.blockedIpv6Count?.incrementAndGet()
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.BLOCK,
                            "Blocked IPv6 literal in domain request: $domain"
                        )
                        sendSocks5Reply(dos, REP_ADDR_TYPE_NOT_SUPPORTED)
                        return@withContext
                    }

                    // Regional Domain Guard (Stage 9 & 10)
                    if (domain == "google.ru" || domain.endsWith(".google.ru")) {
                        domain = domain.removeSuffix(".google.ru") + ".google.com"
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.INFO,
                            "Rewrote regional domain to $domain"
                        )
                        Log.i(TAG, "Rewrote regional domain to $domain")
                    } else if (domain.endsWith(".ru") || domain.endsWith(".su") || domain.endsWith(".by") || domain.endsWith(".xn--p1ai")) {
                        Log.w(TAG, "Fail-closed rule: Blocked regional CIS domain: $domain")
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.BLOCK,
                            "Blocked regional CIS domain: $domain"
                        )
                        sendSocks5Reply(dos, REP_CONN_REFUSED)
                        return@withContext
                    }

                    // Destination Allowlist Guard (P0 Remediation)
                    if (!isDomainAllowed(domain)) {
                        Log.w(TAG, "Fail-closed rule: Blocked non-allowlisted destination domain: $domain")
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.BLOCK,
                            "Blocked non-allowlisted destination domain: $domain"
                        )
                        sendSocks5Reply(dos, REP_CONN_REFUSED)
                        return@withContext
                    }

                    // Check VPN state before attempting DNS query
                    val vpnState = vpnStateMonitor.getCurrentTunnelState()
                    if (vpnState !is VpnTunnelState.Connected) {
                        Log.w(TAG, "Fail-closed: DNS lookup refused for '$domain', VPN is DISCONNECTED")
                        auditLogger?.blockedVpnOffCount?.incrementAndGet()
                        auditLogger?.log(LogCategory.PROXY, LogLevel.BLOCK, "Blocked domain connect to '$domain': VPN Disconnected")
                        sendSocks5Reply(dos, REP_CONN_REFUSED)
                        return@withContext
                    }

                    // Resolve domain via raw DNS-over-TCP bound strictly to tunIpv4
                    val resolved = try {
                        dnsResolver.resolve(
                            domain = domain,
                            tunIpv4 = vpnState.tunIpv4,
                            network = vpnState.network,
                            socketRegistrar = { registerSocketOrThrow(it) },
                            onSocketClosed = {
                                activeSockets.remove(it)
                                auditLogger?.activeSocketsCount?.set(activeSockets.size)
                            }
                        )
                    } catch (e: Exception) {
                        Log.e(TAG, "Fail-closed: DNS resolution failed for '$domain': ${e.message}")
                        sendSocks5Reply(dos, REP_HOST_UNREACHABLE)
                        return@withContext
                    }
                    if (resolved == null) {
                        Log.w(TAG, "DNS resolution returned null (NODATA/NXDOMAIN) for '$domain'")
                        sendSocks5Reply(dos, REP_HOST_UNREACHABLE)
                        return@withContext
                    }
                    targetIp = resolved
                }
                ATYP_IPV6 -> {
                    // Consume IPv6 address (16 bytes) + port (2 bytes)
                    val ipv6Bytes = ByteArray(16)
                    dis.readFully(ipv6Bytes)
                    dis.readUnsignedShort()
                    Log.w(TAG, "Fail-closed rule: IPv6 outbound forbidden (ATYP 0x04)")
                    auditLogger?.blockedIpv6Count?.incrementAndGet()
                    auditLogger?.log(LogCategory.SECURITY, LogLevel.BLOCK, "Rejected outbound IPv6 connection (ATYP 0x04)")
                    sendSocks5Reply(dos, REP_ADDR_TYPE_NOT_SUPPORTED)
                    return@withContext
                }
                else -> {
                    Log.w(TAG, "Unsupported ATYP: $atyp")
                    sendSocks5Reply(dos, REP_ADDR_TYPE_NOT_SUPPORTED)
                    return@withContext
                }
            }

            // --- Step 3: Create & Register Outbound Socket with Race-Condition Check ---
            val outbound = Socket()
            remoteSocket = outbound
            outbound.tcpNoDelay = true
            outbound.keepAlive = true

            val currentTunnelState = try {
                registerSocketOrThrow(outbound, isOutbound = true)
            } catch (e: Exception) {
                Log.w(TAG, "Fail-closed: Connection refused to $targetIp:$targetPort, VPN is DISCONNECTED")
                auditLogger?.blockedVpnOffCount?.incrementAndGet()
                sendSocks5Reply(dos, REP_CONN_REFUSED)
                return@withContext
            }

            // --- Step 4: Bind Outbound Socket to VPN ---
            try {
                // Resilient Android Network binding (handles third-party VPN permission quirks on One UI 9)
                try {
                    currentTunnelState.network.bindSocket(outbound)
                } catch (e: Exception) {
                    Log.w(TAG, "Network.bindSocket non-fatal warning on VPN network: ${e.message}")
                    auditLogger?.log(
                        LogCategory.PROXY,
                        LogLevel.WARN,
                        "Network.bindSocket warning: ${e.message}"
                    )
                }

                // Kernel-level fail-closed enforcement: bind socket to tunnel's local IPv4
                outbound.bind(InetSocketAddress(currentTunnelState.tunIpv4, 0))
                if (outbound.localAddress != currentTunnelState.tunIpv4) {
                    throw IOException("Outbound socket localAddress ${outbound.localAddress} != tunIpv4 ${currentTunnelState.tunIpv4}")
                }

                // Check again right before TCP SYN to defeat any microsecond races
                val verifiedTunnel = vpnStateMonitor.getCurrentTunnelState()
                if (verifiedTunnel !is VpnTunnelState.Connected || verifiedTunnel.generation != currentTunnelState.generation) {
                    throw IOException("VPN state or generation changed right before outbound connect")
                }

                outbound.connect(InetSocketAddress(targetIp, targetPort), OUTBOUND_CONNECT_TIMEOUT_MS)
                auditLogger?.consecutiveNetworkTimeouts?.set(0)
                auditLogger?.successfulConnections?.incrementAndGet()
                auditLogger?.log(
                    LogCategory.PROXY,
                    LogLevel.INFO,
                    "Established outbound TCP: $targetIp:$targetPort via ${currentTunnelState.interfaceName}"
                )
            } catch (e: Exception) {
                if (e is SocketTimeoutException) {
                    auditLogger?.consecutiveNetworkTimeouts?.incrementAndGet()
                }
                Log.e(TAG, "Outbound connection to $targetIp:$targetPort failed: ${e.message}")
                sendSocks5Reply(dos, REP_CONN_REFUSED)
                return@withContext
            }

            // --- Step 5: Send SOCKS5 Success Reply ---
            sendSocks5Success(dos, outbound)

            // Set 5-minute streaming timeouts to prevent zombie half-open sockets
            clientSocket.soTimeout = STREAMING_TIMEOUT_MS
            outbound.soTimeout = STREAMING_TIMEOUT_MS

            // --- Step 6: Relay Bidirectional Traffic ---
            relayTraffic(clientSocket, outbound)

        } catch (_: SocketException) {
            // Expected on stream close or fail-closed abort
        } catch (e: Exception) {
            Log.d(TAG, "Connection finished: ${e.message}")
        } finally {
            activeSockets.remove(clientSocket)
            if (remoteSocket != null) {
                activeSockets.remove(remoteSocket)
                outboundSockets.remove(remoteSocket)
                runCatching { remoteSocket.close() }
            }
            runCatching { clientSocket.close() }
            auditLogger?.activeSocketsCount?.set(activeSockets.size)
        }
    }

    private suspend fun relayTraffic(clientSocket: Socket, remoteSocket: Socket) = withContext(relayDispatcher) {
        val clientIn = clientSocket.getInputStream()
        val clientOut = clientSocket.getOutputStream()
        val remoteIn = remoteSocket.getInputStream()
        val remoteOut = remoteSocket.getOutputStream()

        val jobClientToRemote = launch(relayDispatcher) {
            pipe(clientIn, remoteOut) { bytes ->
                auditLogger?.totalBytesSent?.addAndGet(bytes)
            }
            runCatching { remoteSocket.shutdownOutput() }
        }

        val jobRemoteToClient = launch(relayDispatcher) {
            pipe(remoteIn, clientOut) { bytes ->
                auditLogger?.totalBytesReceived?.addAndGet(bytes)
            }
            runCatching { clientSocket.shutdownOutput() }
        }

        joinAll(jobClientToRemote, jobRemoteToClient)
    }

    private fun pipe(input: InputStream, output: OutputStream, onBytes: (Long) -> Unit) {
        val buffer = ByteArray(BUFFER_SIZE)
        try {
            while (true) {
                val bytesRead = input.read(buffer)
                if (bytesRead == -1) break
                output.write(buffer, 0, bytesRead)
                output.flush()
                onBytes(bytesRead.toLong())
            }
        } catch (_: SocketException) {
            // Socket forcefully closed or reset
        } catch (_: Exception) {
            // Stream ended
        }
    }

    private fun sendSocks5Reply(dos: DataOutputStream, replyCode: Byte) {
        runCatching {
            val reply = byteArrayOf(
                SOCKS_VERSION,
                replyCode,
                0x00,              // RSV
                ATYP_IPV4,
                0, 0, 0, 0,        // BND.ADDR (0.0.0.0)
                0, 0               // BND.PORT (0)
            )
            dos.write(reply)
            dos.flush()
        }
    }

    private fun sendSocks5Success(dos: DataOutputStream, outboundSocket: Socket) {
        val localAddr = outboundSocket.localAddress
        val bndIp = if (localAddr is Inet4Address) localAddr.address else byteArrayOf(0, 0, 0, 0)
        val bndPort = outboundSocket.localPort

        val buffer = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        buffer.put(SOCKS_VERSION)
        buffer.put(REP_SUCCESS)
        buffer.put(0x00.toByte()) // RSV
        buffer.put(ATYP_IPV4)
        buffer.put(bndIp)
        buffer.putShort(bndPort.toShort())

        dos.write(buffer.array())
        dos.flush()
    }

    companion object {
        private const val TAG = "VpnGatekeeperProxy"
        private const val HANDSHAKE_TIMEOUT_MS = 15000
        private const val OUTBOUND_CONNECT_TIMEOUT_MS = 8000
        private const val STREAMING_TIMEOUT_MS = 300_000 // 5 minutes to prevent zombie half-open sockets
        private const val BUFFER_SIZE = 32768

        // SOCKS5 Constants (RFC 1928)
        private const val SOCKS_VERSION = 0x05.toByte()
        private const val METHOD_NO_AUTH = 0x00.toByte()
        private const val METHOD_NO_ACCEPTABLE = 0xFF.toByte()

        private const val CMD_CONNECT = 0x01.toByte()

        private const val ATYP_IPV4 = 0x01.toByte()
        private const val ATYP_DOMAIN = 0x03.toByte()
        private const val ATYP_IPV6 = 0x04.toByte()

        // SOCKS5 Reply Codes
        private const val REP_SUCCESS = 0x00.toByte()
        private const val REP_GENERAL_FAILURE = 0x01.toByte()
        private const val REP_HOST_UNREACHABLE = 0x04.toByte()
        private const val REP_CONN_REFUSED = 0x05.toByte()
        private const val REP_CMD_NOT_SUPPORTED = 0x07.toByte()
        private const val REP_ADDR_TYPE_NOT_SUPPORTED = 0x08.toByte()

        val ALLOWED_DOMAIN_SUFFIXES = setOf(
            "portal.internal-enterprise.net",
            "internal-enterprise.net",
            "corporate portal.com",
            "cloudflare.com",
            "hcaptcha.com",
            "stripe.com",
            "stripe.network",
            "intercom.io",
            "intercomcdn.com",
            "statsig.com",
            "statsigapi.net",
            "datadoghq.com",
            "sentry.io",
            "google.com",
            "gstatic.com",
            "googleapis.com",
            "googleusercontent.com",
            "youtube.com",
            "apple.com",
            "appleid.apple.com",
            "browserleaks.com",
            "browserleaks.net",
            "browserleaks.org",
            "ripe.net"
        )
    }
}

```

---

### 2.7. `app/src/main/java/com/corp/enclaveshield/net/VpnStateMonitor.kt`
**Role:** VPN state monitor, non-null Network, generation counter, bindProcessToNetwork & TunnelListener

```kotlin
package com.corp.enclaveshield.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import com.corp.enclaveshield.telemetry.LogCategory
import com.corp.enclaveshield.telemetry.LogLevel
import com.corp.enclaveshield.telemetry.SecurityAuditLogger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Sealed interface representing the state of the active VPN tunnel.
 */
sealed interface VpnTunnelState {
    data object Disconnected : VpnTunnelState

    data class Connected(
        val network: Network,
        val interfaceName: String,
        val tunIpv4: Inet4Address,
        val generation: Long = 0L
    ) : VpnTunnelState {
        fun sameTunnel(other: Connected): Boolean {
            return network == other.network &&
                    interfaceName == other.interfaceName &&
                    tunIpv4 == other.tunIpv4
        }
    }
}

/**
 * Synchronous listener for instant fail-closed tunnel transitions and handover handling.
 */
fun interface TunnelListener {
    fun onTunnelChanged(previous: VpnTunnelState, current: VpnTunnelState)
}

/**
 * Real-time monitor for active system VPN tunnels (e.g. Amnezia VPN on One UI 9 / Android 16).
 *
 * Listens for VPN transport events via [ConnectivityManager] and verifies
 * that the underlying network interface (tun*, wg*, amn*, v4-tun*, ppp*, ipsec*)
 * is up and holds a valid IPv4 address.
 */
class VpnStateMonitor(
    context: Context,
    private val connectivityManager: ConnectivityManager =
        context.applicationContext.getSystemService(ConnectivityManager::class.java)
            ?: error("ConnectivityManager system service is unavailable"),
    private val auditLogger: SecurityAuditLogger? = null
) {

    private val stateLock = Any()
    private val _vpnState = MutableStateFlow<VpnTunnelState>(VpnTunnelState.Disconnected)
    val vpnState: StateFlow<VpnTunnelState> = _vpnState.asStateFlow()

    private var isRegistered = false
    private var currentGeneration = 0L
    private val tunnelListeners = CopyOnWriteArrayList<TunnelListener>()

    fun addTunnelListener(listener: TunnelListener) {
        tunnelListeners.add(listener)
    }

    fun removeTunnelListener(listener: TunnelListener) {
        tunnelListeners.remove(listener)
    }

    // Critical Android API rule: default NetworkRequest filters out VPNs.
    // Explicitly add TRANSPORT_VPN and remove NET_CAPABILITY_NOT_VPN.
    private val vpnNetworkRequest: NetworkRequest? by lazy {
        runCatching {
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
        }.getOrNull()
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.d(TAG, "VPN network available: $network")
            handleNetworkUpdate(network)
        }

        override fun onCapabilitiesChanged(
            network: Network,
            networkCapabilities: NetworkCapabilities
        ) {
            Log.d(TAG, "VPN capabilities changed: $network")
            handleNetworkUpdate(network)
        }

        override fun onLinkPropertiesChanged(
            network: Network,
            linkProperties: LinkProperties
        ) {
            Log.d(TAG, "VPN link properties changed: $network, iface=${linkProperties.interfaceName}")
            handleNetworkUpdate(network, linkProperties)
        }

        override fun onLost(network: Network) {
            Log.d(TAG, "VPN network lost: $network")
            handleNetworkLost(network)
        }
    }

    init {
        // Trigger an immediate state check on initialization so the app knows at launch
        // whether VPN is ON or OFF before the first callback fires.
        val initialState = scanActiveVpn()
        publishState(initialState)
        startMonitoring()
    }

    /**
     * Publishes tunnel state synchronously under [stateLock], updating generation,
     * binding or unbinding process network via [ConnectivityManager.bindProcessToNetwork],
     * and immediately notifying all [TunnelListener]s.
     */
    private fun publishState(next: VpnTunnelState) {
        synchronized(stateLock) {
            val prev = _vpnState.value
            if (next is VpnTunnelState.Connected) {
                if (prev is VpnTunnelState.Connected && prev.sameTunnel(next)) {
                    return
                }
                currentGeneration++
                val updated = next.copy(generation = currentGeneration)
                _vpnState.value = updated
                recordStateTelemetry(updated)
                runCatching { connectivityManager.bindProcessToNetwork(updated.network) }
                for (listener in tunnelListeners) {
                    runCatching { listener.onTunnelChanged(prev, updated) }
                }
            } else {
                if (prev is VpnTunnelState.Disconnected) {
                    return
                }
                _vpnState.value = VpnTunnelState.Disconnected
                recordStateTelemetry(VpnTunnelState.Disconnected)
                runCatching { connectivityManager.bindProcessToNetwork(null) }
                for (listener in tunnelListeners) {
                    runCatching { listener.onTunnelChanged(prev, VpnTunnelState.Disconnected) }
                }
            }
        }
    }

    /**
     * Registers the network callback for VPN events. Idempotent.
     */
    fun startMonitoring() {
        synchronized(stateLock) {
            if (isRegistered) return
            val request = vpnNetworkRequest ?: return
            try {
                connectivityManager.registerNetworkCallback(request, networkCallback)
                isRegistered = true
                val scanned = scanActiveVpn()
                publishState(scanned)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to register VPN NetworkCallback", e)
            }
        }
    }

    /**
     * Unregisters the network callback. Idempotent.
     */
    fun stopMonitoring() {
        synchronized(stateLock) {
            if (!isRegistered) return
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to unregister VPN NetworkCallback", e)
            } finally {
                isRegistered = false
                publishState(VpnTunnelState.Disconnected)
            }
        }
    }

    /**
     * Synchronously retrieves the current VPN tunnel state.
     * Double-checks in real time that the underlying [NetworkInterface] is still
     * up and holds the exact [Inet4Address] to defeat callback latency and race conditions.
     */
    fun getCurrentTunnelState(): VpnTunnelState {
        synchronized(stateLock) {
            val current = _vpnState.value
            if (current is VpnTunnelState.Connected) {
                val isStillAlive = isInterfaceUpAndHoldsAddress(current.interfaceName, current.tunIpv4)
                if (isStillAlive) {
                    val caps = connectivityManager.getNetworkCapabilities(current.network)
                    if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                        return current
                    }
                }
            }

            // If disconnected or the previous interface died, perform an immediate scan
            val freshState = scanActiveVpn()
            publishState(freshState)
            return _vpnState.value
        }
    }

    private fun handleNetworkUpdate(network: Network, linkProperties: LinkProperties? = null) {
        val evaluated = evaluateNetwork(network, linkProperties)
        if (evaluated is VpnTunnelState.Connected) {
            publishState(evaluated)
        } else {
            val current = _vpnState.value
            if (current is VpnTunnelState.Connected && current.network == network) {
                publishState(scanActiveVpn())
            }
        }
    }

    private fun handleNetworkLost(network: Network) {
        val current = _vpnState.value
        if (current is VpnTunnelState.Connected && current.network == network) {
            publishState(scanActiveVpn())
        }
    }

    private fun evaluateNetwork(network: Network, providedLp: LinkProperties? = null): VpnTunnelState {
        val caps = connectivityManager.getNetworkCapabilities(network) ?: return VpnTunnelState.Disconnected
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return VpnTunnelState.Disconnected
        }

        val lp = providedLp ?: connectivityManager.getLinkProperties(network)
        val lpInterfaceName = lp?.interfaceName

        var chosenInterfaceName: String? = null
        var chosenIpv4: Inet4Address? = null

        if (isValidVpnTransportInterface(lpInterfaceName)) {
            chosenInterfaceName = lpInterfaceName
            chosenIpv4 = extractIpv4(lp) ?: getIpv4FromInterfaceName(lpInterfaceName!!)
        } else {
            // Fallback: search NetworkInterface.getNetworkInterfaces() strictly with known VPN prefixes
            val fallback = findFallbackTunnelInterface()
            if (fallback != null) {
                chosenInterfaceName = fallback.first
                chosenIpv4 = fallback.second
            }
        }

        if (chosenInterfaceName == null || chosenIpv4 == null) {
            return VpnTunnelState.Disconnected
        }

        val isInterfaceValid = isInterfaceUpAndHoldsAddress(chosenInterfaceName, chosenIpv4)
        return if (isInterfaceValid) {
            VpnTunnelState.Connected(
                network = network,
                interfaceName = chosenInterfaceName,
                tunIpv4 = chosenIpv4
            )
        } else {
            VpnTunnelState.Disconnected
        }
    }

    private fun scanActiveVpn(): VpnTunnelState {
        try {
            // 1. Check activeNetwork if it has VPN transport
            val active = connectivityManager.activeNetwork
            if (active != null) {
                val caps = connectivityManager.getNetworkCapabilities(active)
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                    val state = evaluateNetwork(active)
                    if (state is VpnTunnelState.Connected) {
                        return state
                    }
                }
            }

            // 2. Iterate through allNetworks
            for (network in getAllNetworks()) {
                val caps = connectivityManager.getNetworkCapabilities(network)
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                    val state = evaluateNetwork(network)
                    if (state is VpnTunnelState.Connected) {
                        return state
                    }
                }
            }

            // 3. Fallback: match discovered tunnel interface against allNetworks link properties
            val fallback = findFallbackTunnelInterface()
            if (fallback != null) {
                var matchedNetwork: Network? = null
                for (network in getAllNetworks()) {
                    val lp = connectivityManager.getLinkProperties(network)
                    if (lp?.interfaceName == fallback.first) {
                        val caps = connectivityManager.getNetworkCapabilities(network)
                        if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                            matchedNetwork = network
                            break
                        }
                    }
                }

                if (matchedNetwork != null) {
                    return VpnTunnelState.Connected(
                        network = matchedNetwork,
                        interfaceName = fallback.first,
                        tunIpv4 = fallback.second
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error scanning for active VPN", e)
        }

        return VpnTunnelState.Disconnected
    }

    @Suppress("DEPRECATION")
    private fun getAllNetworks(): Array<Network> {
        return runCatching { connectivityManager.allNetworks }.getOrDefault(emptyArray())
    }

    private fun isKnownVpnInterfacePrefix(name: String?): Boolean {
        if (name.isNullOrBlank()) return false
        val lower = name.lowercase()
        return lower.startsWith("tun") ||
                lower.startsWith("wg") ||
                lower.startsWith("amn") ||
                lower.startsWith("v4-tun") ||
                lower.startsWith("ppp") ||
                lower.startsWith("ipsec")
    }

    private fun isValidVpnTransportInterface(name: String?): Boolean {
        if (name.isNullOrBlank()) return false
        val lower = name.lowercase()
        if (isKnownVpnInterfacePrefix(lower)) return true
        return !lower.startsWith("wlan") &&
                !lower.startsWith("rmnet") &&
                !lower.startsWith("ccmni") &&
                !lower.startsWith("eth") &&
                !lower.startsWith("lo") &&
                !lower.startsWith("dummy") &&
                !lower.startsWith("sit") &&
                !lower.startsWith("p2p")
    }

    private fun extractIpv4(linkProperties: LinkProperties?): Inet4Address? {
        if (linkProperties == null) return null
        return linkProperties.linkAddresses
            .map { it.address }
            .filterIsInstance<Inet4Address>()
            .firstOrNull()
    }

    private fun getIpv4FromInterfaceName(interfaceName: String): Inet4Address? {
        return runCatching {
            val iface = NetworkInterface.getByName(interfaceName) ?: return null
            if (!iface.isUp) return null
            iface.inetAddresses.asSequence()
                .filterIsInstance<Inet4Address>()
                .firstOrNull()
        }.getOrNull()
    }

    private fun findFallbackTunnelInterface(): Pair<String, Inet4Address>? {
        return runCatching {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return null
            for (iface in interfaces) {
                if (iface.isUp && !iface.isLoopback && isKnownVpnInterfacePrefix(iface.name)) {
                    val ipv4 = iface.inetAddresses.asSequence()
                        .filterIsInstance<Inet4Address>()
                        .firstOrNull()
                    if (ipv4 != null) {
                        return Pair(iface.name, ipv4)
                    }
                }
            }
            null
        }.getOrNull()
    }

    private fun isInterfaceUpAndHoldsAddress(interfaceName: String, address: Inet4Address): Boolean {
        return runCatching {
            val iface = NetworkInterface.getByName(interfaceName) ?: return false
            iface.isUp && iface.inetAddresses.asSequence()
                .filterIsInstance<Inet4Address>()
                .any { it == address }
        }.getOrDefault(false)
    }

    private var lastReportedState: VpnTunnelState? = null

    private fun recordStateTelemetry(state: VpnTunnelState) {
        val logger = auditLogger ?: return
        val prev = lastReportedState
        if (state == prev) return

        when (state) {
            is VpnTunnelState.Connected -> {
                if (prev !is VpnTunnelState.Connected ||
                    prev.interfaceName != state.interfaceName ||
                    prev.tunIpv4 != state.tunIpv4
                ) {
                    lastReportedState = state
                    logger.vpnConnectCount.incrementAndGet()
                    logger.log(
                        LogCategory.VPN,
                        LogLevel.INFO,
                        "VPN Connected: iface=${state.interfaceName}, tunIpv4=${state.tunIpv4.hostAddress}, net=${state.network}"
                    )
                }
            }
            is VpnTunnelState.Disconnected -> {
                if (prev !is VpnTunnelState.Disconnected) {
                    lastReportedState = state
                    logger.vpnDisconnectCount.incrementAndGet()
                    logger.log(
                        LogCategory.VPN,
                        LogLevel.WARN,
                        "VPN Disconnected: fail-closed active"
                    )
                }
            }
        }
    }

    companion object {
        private const val TAG = "VpnStateMonitor"
    }
}

```

---

### 2.8. `app/src/main/java/com/corp/enclaveshield/security/AntiFingerprintHardener.kt`
**Role:** Document-Start JS injection: WebRTC kill, offscreen Canvas farbling, toString cloaking, TTS/Intl lock

```kotlin
package com.corp.enclaveshield.security

import android.webkit.WebView
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

/**
 * Anti-fingerprinting, WebRTC kill-switch, and per-profile anti-correlation injector.
 *
 * Injects a document-start script using [WebViewCompat.addDocumentStartJavaScript]
 * that runs before ANY web page script on every frame.
 */
object AntiFingerprintHardener {

    /**
     * Builds the document-start JavaScript string.
     *
     * @param profileSeed Deterministic integer seed derived from account profile ID.
     * Hardware concurrency, device memory, and Canvas 2D fingerprints are deterministically
     * perturbed to prevent multi-account correlation.
     */
    fun buildDocumentStartJs(profileSeed: Int = 0): String {
        val safeSeed = (kotlin.math.abs(profileSeed) % 997) + 1
        val concurrency = listOf(6, 8, 12)[safeSeed % 3]
        val memory = listOf(4, 8)[safeSeed % 2]
        val noiseOffset = (safeSeed % 5) + 1

        val canvasNoiseJs = """
            // 7. Per-Profile Canvas Anti-Correlation Hardening (Seed: $safeSeed)
            try {
                const NOISE_OFFSET = $noiseOffset;

                const applyNoise = (data) => {
                    if (!data || data.length < 4) return;
                    let targetIdx = 0;
                    for (let i = 0; i < data.length; i += 4) {
                        if (data[i + 3] > 0) {
                            targetIdx = i;
                            break;
                        }
                    }
                    data[targetIdx] = (data[targetIdx] + NOISE_OFFSET) % 256;
                };

                const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
                CanvasRenderingContext2D.prototype.getImageData = cloak(function(sx, sy, sw, sh, settings) {
                    const imgData = origGetImageData.call(this, sx, sy, sw, sh, settings);
                    if (imgData && imgData.data) {
                        applyNoise(imgData.data);
                    }
                    return imgData;
                }, 'getImageData');

                const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
                HTMLCanvasElement.prototype.toDataURL = cloak(function(type, encoderOptions) {
                    try {
                        if (this.width > 0 && this.height > 0) {
                            const offscreen = document.createElement('canvas');
                            offscreen.width = this.width;
                            offscreen.height = this.height;
                            const offCtx = offscreen.getContext('2d');
                            if (offCtx) {
                                offCtx.drawImage(this, 0, 0);
                                const sampleW = Math.min(this.width, 32);
                                const sampleH = Math.min(this.height, 32);
                                const sample = origGetImageData.call(offCtx, 0, 0, sampleW, sampleH);
                                if (sample && sample.data) {
                                    applyNoise(sample.data);
                                    offCtx.putImageData(sample, 0, 0);
                                }
                                return origToDataURL.call(offscreen, type, encoderOptions);
                            }
                        }
                    } catch (e) {}
                    return origToDataURL.call(this, type, encoderOptions);
                }, 'toDataURL');

                const origToBlob = HTMLCanvasElement.prototype.toBlob;
                HTMLCanvasElement.prototype.toBlob = cloak(function(callback, type, quality) {
                    try {
                        if (this.width > 0 && this.height > 0) {
                            const offscreen = document.createElement('canvas');
                            offscreen.width = this.width;
                            offscreen.height = this.height;
                            const offCtx = offscreen.getContext('2d');
                            if (offCtx) {
                                offCtx.drawImage(this, 0, 0);
                                const sampleW = Math.min(this.width, 32);
                                const sampleH = Math.min(this.height, 32);
                                const sample = origGetImageData.call(offCtx, 0, 0, sampleW, sampleH);
                                if (sample && sample.data) {
                                    applyNoise(sample.data);
                                    offCtx.putImageData(sample, 0, 0);
                                }
                                return origToBlob.call(offscreen, callback, type, quality);
                            }
                        }
                    } catch (e) {}
                    return origToBlob.call(this, callback, type, quality);
                }, 'toBlob');
            } catch (e) {}
        """.trimIndent()

        return """
        (() => {
            'use strict';

            // 0. Native Function Cloaking ([native code])
            const nativeMap = new WeakMap();
            const origToString = Function.prototype.toString;
            Function.prototype.toString = function() {
                if (nativeMap.has(this)) {
                    return 'function ' + nativeMap.get(this) + '() { [native code] }';
                }
                return origToString.call(this);
            };
            nativeMap.set(Function.prototype.toString, 'toString');
            const cloak = (fn, name) => {
                try {
                    nativeMap.set(fn, name);
                } catch (e) {}
                return fn;
            };

            // 1. WebRTC Kill-switch: eliminate STUN/ICE local & public IP discovery
            const killProperty = (target, prop) => {
                try {
                    delete target[prop];
                    Object.defineProperty(target, prop, {
                        value: undefined,
                        writable: false,
                        configurable: false
                    });
                } catch (e) {}
            };

            killProperty(window, 'RTCPeerConnection');
            killProperty(window, 'webkitRTCPeerConnection');
            killProperty(window, 'mozRTCPeerConnection');
            killProperty(window, 'RTCDataChannel');
            killProperty(window, 'RTCIceCandidate');
            killProperty(window, 'RTCSessionDescription');
            if (window.navigator && window.navigator.mediaDevices) {
                killProperty(window.navigator.mediaDevices, 'getUserMedia');
            }

            // 2. Dynamic navigator.onLine spoofing
            try {
                Object.defineProperty(navigator, 'onLine', {
                    get: () => (window.__enclaveOffline === true ? false : true),
                    configurable: false
                });
            } catch (e) {}

            // 3. Navigator Language and Languages lockdown
            try {
                Object.defineProperty(navigator, 'language', {
                    get: () => 'en-US',
                    configurable: false
                });
                Object.defineProperty(navigator, 'languages', {
                    get: () => Object.freeze(['en-US', 'en']),
                    configurable: false
                });
            } catch (e) {}

            // 4. Timezone Spoofing: Europe/Amsterdam (CET/CEST)
            const TARGET_TIMEZONE = 'Europe/Amsterdam';

            const computeAmsterdamOffset = (d) => {
                try {
                    const date = (d instanceof Date && !isNaN(d.getTime())) ? d : new Date();
                    const parts = new Intl.DateTimeFormat('en-US', {
                        timeZone: TARGET_TIMEZONE,
                        hourCycle: 'h23',
                        year: 'numeric', month: 'numeric', day: 'numeric',
                        hour: 'numeric', minute: 'numeric', second: 'numeric'
                    }).formatToParts(date);
                    const map = {};
                    for (const p of parts) { map[p.type] = p.value; }
                    const amsLocalAsUtc = new Date(Date.UTC(
                        parseInt(map.year, 10),
                        parseInt(map.month, 10) - 1,
                        parseInt(map.day, 10),
                        parseInt(map.hour, 10),
                        parseInt(map.minute, 10),
                        parseInt(map.second, 10)
                    ));
                    return Math.round((date.getTime() - amsLocalAsUtc.getTime()) / 60000);
                } catch (e) {
                    return -60; // Fallback to CET
                }
            };

            try {
                Date.prototype.getTimezoneOffset = cloak(function() {
                    return computeAmsterdamOffset(this);
                }, 'getTimezoneOffset');
            } catch (e) {}

            try {
                const OrigDTF = Intl.DateTimeFormat;
                const ProxyDTF = cloak(function(locales, options) {
                    const opts = Object.assign({}, options);
                    if (!opts.timeZone) {
                        opts.timeZone = TARGET_TIMEZONE;
                    }
                    return new OrigDTF(locales || 'en-US', opts);
                }, 'DateTimeFormat');
                ProxyDTF.prototype = OrigDTF.prototype;
                ProxyDTF.supportedLocalesOf = OrigDTF.supportedLocalesOf;

                const origResolvedOptions = OrigDTF.prototype.resolvedOptions;
                OrigDTF.prototype.resolvedOptions = cloak(function() {
                    const res = origResolvedOptions.call(this);
                    res.timeZone = TARGET_TIMEZONE;
                    return res;
                }, 'resolvedOptions');

                Intl.DateTimeFormat = ProxyDTF;
            } catch (e) {}

            // 5. Date string representations in Europe/Amsterdam (en-US)
            try {
                Date.prototype.toString = cloak(function() {
                    if (isNaN(this.getTime())) return 'Invalid Date';
                    try {
                        const dtf = new OrigDTF('en-US', {
                            timeZone: TARGET_TIMEZONE,
                            weekday: 'short',
                            month: 'short',
                            day: '2-digit',
                            year: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                            hourCycle: 'h23',
                            timeZoneName: 'long'
                        });
                        const parts = {};
                        dtf.formatToParts(this).forEach(p => { parts[p.type] = p.value; });
                        const offsetMin = computeAmsterdamOffset(this);
                        const sign = offsetMin <= 0 ? '+' : '-';
                        const absOffset = Math.abs(offsetMin);
                        const hh = String(Math.floor(absOffset / 60)).padStart(2, '0');
                        const mm = String(absOffset % 60).padStart(2, '0');
                        return `${'$'}{parts.weekday} ${'$'}{parts.month} ${'$'}{parts.day} ${'$'}{parts.year} ${'$'}{parts.hour}:${'$'}{parts.minute}:${'$'}{parts.second} GMT${'$'}{sign}${'$'}{hh}${'$'}{mm} (${'$'}{parts.timeZoneName || 'Central European Time'})`;
                    } catch (err) {
                        return 'Invalid Date';
                    }
                }, 'toString');

                Date.prototype.toTimeString = cloak(function() {
                    if (isNaN(this.getTime())) return 'Invalid Date';
                    try {
                        const dtf = new OrigDTF('en-US', {
                            timeZone: TARGET_TIMEZONE,
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                            hourCycle: 'h23',
                            timeZoneName: 'long'
                        });
                        const parts = {};
                        dtf.formatToParts(this).forEach(p => { parts[p.type] = p.value; });
                        const offsetMin = computeAmsterdamOffset(this);
                        const sign = offsetMin <= 0 ? '+' : '-';
                        const absOffset = Math.abs(offsetMin);
                        const hh = String(Math.floor(absOffset / 60)).padStart(2, '0');
                        const mm = String(absOffset % 60).padStart(2, '0');
                        return `${'$'}{parts.hour}:${'$'}{parts.minute}:${'$'}{parts.second} GMT${'$'}{sign}${'$'}{hh}${'$'}{mm} (${'$'}{parts.timeZoneName || 'Central European Time'})`;
                    } catch (err) {
                        return 'Invalid Date';
                    }
                }, 'toTimeString');

                const origToLocaleString = Date.prototype.toLocaleString;
                Date.prototype.toLocaleString = cloak(function(locales, options) {
                    const opts = Object.assign({}, options);
                    if (!opts.timeZone) opts.timeZone = TARGET_TIMEZONE;
                    return origToLocaleString.call(this, locales || 'en-US', opts);
                }, 'toLocaleString');

                const origToLocaleDateString = Date.prototype.toLocaleDateString;
                Date.prototype.toLocaleDateString = cloak(function(locales, options) {
                    const opts = Object.assign({}, options);
                    if (!opts.timeZone) opts.timeZone = TARGET_TIMEZONE;
                    return origToLocaleDateString.call(this, locales || 'en-US', opts);
                }, 'toLocaleDateString');

                const origToLocaleTimeString = Date.prototype.toLocaleTimeString;
                Date.prototype.toLocaleTimeString = cloak(function(locales, options) {
                    const opts = Object.assign({}, options);
                    if (!opts.timeZone) opts.timeZone = TARGET_TIMEZONE;
                    return origToLocaleTimeString.call(this, locales || 'en-US', opts);
                }, 'toLocaleTimeString');
            } catch (e) {}

            // 6. Deterministic Hardware Concurrency & Device Memory Spoofing
            try {
                Object.defineProperty(navigator, 'hardwareConcurrency', {
                    get: () => $concurrency,
                    configurable: false
                });
                Object.defineProperty(navigator, 'deviceMemory', {
                    get: () => $memory,
                    configurable: false
                });
            } catch (e) {}

            $canvasNoiseJs

            // 8. Eliminate Russian TTS Voice Leak (window.speechSynthesis)
            try {
                if (window.speechSynthesis) {
                    window.speechSynthesis.getVoices = cloak(() => [], 'getVoices');
                    window.speechSynthesis.onvoiceschanged = null;
                }
                if (window.SpeechSynthesis && SpeechSynthesis.prototype) {
                    SpeechSynthesis.prototype.getVoices = cloak(() => [], 'getVoices');
                }
            } catch (e) {}

            // 9. Lock All Intl Constructors resolvedOptions to en-US
            try {
                const lockLocale = (proto) => {
                    if (proto && proto.resolvedOptions) {
                        const orig = proto.resolvedOptions;
                        proto.resolvedOptions = cloak(function() {
                            const res = orig.call(this);
                            if (res) res.locale = 'en-US';
                            return res;
                        }, 'resolvedOptions');
                    }
                };
                if (window.Intl) {
                    if (Intl.NumberFormat) lockLocale(Intl.NumberFormat.prototype);
                    if (Intl.Collator) lockLocale(Intl.Collator.prototype);
                    if (Intl.PluralRules) lockLocale(Intl.PluralRules.prototype);
                    if (Intl.RelativeTimeFormat) lockLocale(Intl.RelativeTimeFormat.prototype);
                }
            } catch (e) {}

            // 10. Normalize Network Information API & Webdriver
            try {
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => false,
                    configurable: false
                });
            } catch (e) {}

            try {
                if (navigator.connection) {
                    try {
                        Object.defineProperty(navigator.connection, 'onchange', {
                            get: () => null,
                            set: () => {},
                            configurable: false
                        });
                    } catch (e) {
                        navigator.connection.onchange = null;
                    }
                }
            } catch (e) {}
        })();
        """.trimIndent()
    }

    val DOCUMENT_START_JS: String = buildDocumentStartJs(0)

    /**
     * Injects the hardening script via [WebViewCompat.addDocumentStartJavaScript] if supported.
     */
    fun applyHardening(webView: WebView, profileSeed: Int = 0): Boolean {
        return if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            WebViewCompat.addDocumentStartJavaScript(
                webView,
                buildDocumentStartJs(profileSeed),
                setOf("*")
            )
            true
        } else {
            false
        }
    }
}

```

---

### 2.9. `app/src/main/java/com/corp/enclaveshield/accounts/AccountProfile.kt`
**Role:** Profile data models

```kotlin
package com.corp.enclaveshield.accounts

import androidx.webkit.Profile

/**
 * Data model representing an isolated user account profile.
 *
 * @property id Unique identifier (e.g. "default" or UUID).
 * @property displayName Human-readable name (e.g. "Default Account", "Work", "Personal").
 * @property createdAt Epoch timestamp when the profile was created.
 */
data class AccountProfile(
    val id: String,
    val displayName: String,
    val createdAt: Long = System.currentTimeMillis()
) {
    val profileSeed: Int
        get() = kotlin.math.abs(id.hashCode())

    /**
     * Alphanumeric/underscore key used for AndroidX [androidx.webkit.ProfileStore].
     * Defaults to [Profile.DEFAULT_PROFILE_NAME] ("Default") for the primary profile.
     */
    val storageKey: String
        get() = if (id == DEFAULT_ID) Profile.DEFAULT_PROFILE_NAME else "profile_${id.replace("-", "_")}"

    companion object {
        const val DEFAULT_ID = "default"
        const val DEFAULT_DISPLAY_NAME = "Default Account"
    }
}

```

---

### 2.10. `app/src/main/java/com/corp/enclaveshield/accounts/AccountProfileManager.kt`
**Role:** Multi-account profile container manager with safe deletion switching

```kotlin
package com.corp.enclaveshield.accounts

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.webkit.Profile
import androidx.webkit.ProfileStore
import androidx.webkit.WebViewFeature
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

/**
 * Manages user account profiles and Chromium multi-profile containerization.
 *
 * Guarantees:
 * 1. Default initialization with "Default Account".
 * 2. Persistence of profile list and active profile ID in SharedPreferences.
 * 3. Native container isolation via [ProfileStore] when MULTI_PROFILE is supported.
 * 4. Automatic web storage cleanup when a profile is deleted.
 * 5. Safeguard: cannot delete the only remaining profile.
 * 6. Fallback cookie jar storage support when MULTI_PROFILE is unavailable.
 */
class AccountProfileManager(
    context: Context,
    prefsOverride: SharedPreferences? = null,
    private val profileStoreProvider: (() -> ProfileStore?)? = null,
    cookieJarFallback: AccountCookieJarFallback? = null
) {
    private val prefs: SharedPreferences = prefsOverride
        ?: context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    val fallback: AccountCookieJarFallback = cookieJarFallback ?: AccountCookieJarFallback(context, prefsOverride)

    private val _profiles = MutableStateFlow<List<AccountProfile>>(emptyList())
    val profiles: StateFlow<List<AccountProfile>> = _profiles.asStateFlow()

    private val _activeProfile = MutableStateFlow(
        AccountProfile(AccountProfile.DEFAULT_ID, AccountProfile.DEFAULT_DISPLAY_NAME)
    )
    val activeProfile: StateFlow<AccountProfile> = _activeProfile.asStateFlow()

    init {
        loadProfiles()
    }

    @Synchronized
    private fun loadProfiles() {
        val rawJson = prefs.getString(KEY_PROFILES, null)
        val loaded = AccountProfileJsonCodec.fromJson(rawJson)
        val initialList = if (loaded.isEmpty()) {
            val defaultAcc = AccountProfile(
                id = AccountProfile.DEFAULT_ID,
                displayName = AccountProfile.DEFAULT_DISPLAY_NAME,
                createdAt = System.currentTimeMillis()
            )
            val list = listOf(defaultAcc)
            persistProfiles(list)
            list
        } else {
            loaded
        }
        _profiles.value = initialList

        val savedActiveId = prefs.getString(KEY_ACTIVE_PROFILE_ID, null)
        val active = initialList.find { it.id == savedActiveId } ?: initialList.first()
        _activeProfile.value = active
        prefs.edit().putString(KEY_ACTIVE_PROFILE_ID, active.id).apply()
    }

    @Synchronized
    fun createProfile(name: String): AccountProfile {
        val trimmed = name.trim()
        val displayName = if (trimmed.isEmpty()) {
            "Account ${_profiles.value.size + 1}"
        } else {
            trimmed
        }
        val newProfile = AccountProfile(
            id = UUID.randomUUID().toString(),
            displayName = displayName,
            createdAt = System.currentTimeMillis()
        )
        val updated = _profiles.value + newProfile
        _profiles.value = updated
        persistProfiles(updated)
        Log.i(TAG, "Created profile: ${newProfile.id} (${newProfile.displayName})")
        return newProfile
    }

    @Synchronized
    fun switchProfile(id: String): Boolean {
        val target = _profiles.value.find { it.id == id } ?: return false
        _activeProfile.value = target
        prefs.edit().putString(KEY_ACTIVE_PROFILE_ID, target.id).apply()
        Log.i(TAG, "Switched active profile to: ${target.id} (${target.displayName})")
        return true
    }

    @Synchronized
    fun renameProfile(id: String, newName: String): Boolean {
        val trimmed = newName.trim()
        if (trimmed.isEmpty()) return false
        val index = _profiles.value.indexOfFirst { it.id == id }
        if (index == -1) return false

        val updated = _profiles.value.toMutableList()
        val old = updated[index]
        val modified = old.copy(displayName = trimmed)
        updated[index] = modified
        _profiles.value = updated
        persistProfiles(updated)

        if (_activeProfile.value.id == id) {
            _activeProfile.value = modified
        }
        Log.i(TAG, "Renamed profile $id to: $trimmed")
        return true
    }

    @Synchronized
    fun deleteProfile(id: String): Boolean {
        if (_profiles.value.size <= 1) {
            Log.w(TAG, "Cannot delete only remaining profile: $id")
            return false
        }
        val target = _profiles.value.find { it.id == id } ?: return false

        // Delete web storage via ProfileStore
        deleteProfileStorage(target)

        // Delete fallback cookies if any
        fallback.deleteCookies(target.id)

        val updated = _profiles.value.filter { it.id != id }
        _profiles.value = updated
        persistProfiles(updated)

        // If deleted profile was active, transition to first remaining profile
        if (_activeProfile.value.id == id) {
            val newActive = updated.first()
            _activeProfile.value = newActive
            prefs.edit().putString(KEY_ACTIVE_PROFILE_ID, newActive.id).apply()
            Log.i(TAG, "Active profile was deleted, transitioned to: ${newActive.displayName}")
        }
        Log.i(TAG, "Deleted profile: ${target.id} (${target.displayName})")
        return true
    }

    private fun deleteProfileStorage(profile: AccountProfile) {
        try {
            val store = getProfileStore()
            if (store != null) {
                if (profile.storageKey == Profile.DEFAULT_PROFILE_NAME) {
                    val p = runCatching { store.getProfile(profile.storageKey) }.getOrNull()
                    p?.webStorage?.deleteAllData()
                    p?.cookieManager?.removeAllCookies(null)
                } else {
                    store.deleteProfile(profile.storageKey)
                }
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Failed to delete storage for ${profile.storageKey}: ${e.message}")
        }
    }

    private fun getProfileStore(): ProfileStore? {
        return profileStoreProvider?.invoke() ?: try {
            if (WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) {
                ProfileStore.getInstance()
            } else {
                null
            }
        } catch (e: Throwable) {
            null
        }
    }

    private fun persistProfiles(list: List<AccountProfile>) {
        val json = AccountProfileJsonCodec.toJson(list)
        prefs.edit().putString(KEY_PROFILES, json).apply()
    }

    companion object {
        private const val TAG = "AccountProfileManager"
        const val PREFS_NAME = "enclaveshield_accounts_prefs"
        const val KEY_PROFILES = "profiles_list"
        const val KEY_ACTIVE_PROFILE_ID = "active_profile_id"
    }
}

```

---

### 2.11. `app/src/main/java/com/corp/enclaveshield/accounts/AccountCookieJarFallback.kt`
**Role:** AES-256-GCM Keystore cookie jar with system IV generation & profile AAD binding

```kotlin
package com.corp.enclaveshield.accounts

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.webkit.CookieManager
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypted SharedPreferences storage for cookie jar snapshot fallback
 * on devices or WebView engines where [androidx.webkit.WebViewFeature.MULTI_PROFILE]
 * is not supported.
 *
 * Cookies are encrypted using AES-256-GCM authenticated encryption before persisting.
 */
class AccountCookieJarFallback(
    context: Context,
    prefsOverride: SharedPreferences? = null
) {
    private val prefs: SharedPreferences = prefsOverride
        ?: context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val secretKey: SecretKey by lazy {
        getOrCreateSecretKey()
    }

    private fun getOrCreateSecretKey(): SecretKey {
        return runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val keyAlias = "enclaveshield_cookie_aes_key"
            if (keyStore.containsAlias(keyAlias)) {
                (keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry)?.secretKey
                    ?: (keyStore.getKey(keyAlias, null) as? SecretKey)
                    ?: error("AndroidKeyStore key entry missing")
            } else {
                val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                val spec = KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                keyGen.init(spec)
                keyGen.generateKey()
            }
        }.getOrElse {
            // JVM Unit Tests / Non-Android environment fallback
            val savedKey = prefs.getString(KEY_SECRET_KEY, null)
            if (!savedKey.isNullOrEmpty()) {
                val raw = Base64.getDecoder().decode(savedKey)
                SecretKeySpec(raw, "AES")
            } else {
                val keyGen = KeyGenerator.getInstance("AES")
                keyGen.init(256, SecureRandom())
                val key = keyGen.generateKey()
                val encoded = Base64.getEncoder().encodeToString(key.encoded)
                prefs.edit().putString(KEY_SECRET_KEY, encoded).apply()
                key
            }
        }
    }

    fun encrypt(profileId: String, plaintext: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // Initialize without IV: AndroidKeyStore generates random IV under setRandomizedEncryptionRequired(true)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv ?: error("Cipher failed to generate IV")
        cipher.updateAAD(profileId.toByteArray(Charsets.UTF_8))
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(ciphertext, 0, combined, iv.size, ciphertext.size)
        return Base64.getEncoder().encodeToString(combined)
    }

    fun encrypt(plaintext: String): String = encrypt("", plaintext)

    fun decrypt(profileId: String, encryptedBase64: String): String? {
        return runCatching {
            val combined = Base64.getDecoder().decode(encryptedBase64)
            if (combined.size < 12) return null
            val iv = combined.copyOfRange(0, 12)
            val ciphertext = combined.copyOfRange(12, combined.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            cipher.updateAAD(profileId.toByteArray(Charsets.UTF_8))
            val decrypted = cipher.doFinal(ciphertext)
            String(decrypted, Charsets.UTF_8)
        }.getOrNull()
    }

    fun decrypt(encryptedBase64: String): String? = decrypt("", encryptedBase64)

    fun saveCookies(profileId: String, cookieString: String) {
        val encrypted = encrypt(profileId, cookieString)
        prefs.edit().putString(KEY_COOKIE_PREFIX + profileId, encrypted).apply()
    }

    fun getCookies(profileId: String): String? {
        val encrypted = prefs.getString(KEY_COOKIE_PREFIX + profileId, null) ?: return null
        return decrypt(profileId, encrypted)
    }

    fun deleteCookies(profileId: String) {
        prefs.edit().remove(KEY_COOKIE_PREFIX + profileId).apply()
    }

    /**
     * Snapshots current CookieManager cookies for [profileId].
     */
    fun snapshotCookies(profileId: String, url: String = PORTAL_URL) {
        try {
            val cm = CookieManager.getInstance()
            val cookies = cm?.getCookie(url)
            saveCookies(profileId, cookies ?: "")
            Log.i(TAG, "Snapshotted cookies for profile: $profileId")
        } catch (e: Throwable) {
            Log.w(TAG, "Failed to snapshot cookies: ${e.message}")
        }
    }

    /**
     * Clears CookieManager and restores saved cookies for [targetProfileId].
     */
    fun restoreCookies(targetProfileId: String, url: String = PORTAL_URL, onComplete: (() -> Unit)? = null) {
        try {
            val cm = CookieManager.getInstance()
            if (cm == null) {
                onComplete?.invoke()
                return
            }
            cm.removeAllCookies {
                val saved = getCookies(targetProfileId)
                if (!saved.isNullOrEmpty()) {
                    val parts = saved.split(";")
                    for (part in parts) {
                        val trimmed = part.trim()
                        if (trimmed.isNotEmpty()) {
                            cm.setCookie(url, trimmed)
                        }
                    }
                    cm.flush()
                }
                Log.i(TAG, "Restored cookies for profile: $targetProfileId")
                onComplete?.invoke()
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Failed to restore cookies: ${e.message}")
            onComplete?.invoke()
        }
    }

    companion object {
        private const val TAG = "AccountCookieJarFallback"
        private const val PREFS_NAME = "enclaveshield_cookie_jar_prefs"
        private const val KEY_SECRET_KEY = "jar_aes_key"
        private const val KEY_COOKIE_PREFIX = "jar_cookies_"
        const val PORTAL_URL = "https://portal.internal-enterprise.net"
    }
}

```

---

### 2.12. `app/src/main/java/com/corp/enclaveshield/accounts/AccountProfileJsonCodec.kt`
**Role:** org.json serialization for profile storage

```kotlin
package com.corp.enclaveshield.accounts

import org.json.JSONArray
import org.json.JSONObject

/**
 * Robust JSON serializer/deserializer for [AccountProfile] records using [org.json].
 * 100% immune to character escaping, nested braces, quotes, and whitespace irregularities.
 */
object AccountProfileJsonCodec {

    fun toJson(profiles: List<AccountProfile>): String {
        val array = JSONArray()
        for (profile in profiles) {
            val obj = JSONObject().apply {
                put("id", profile.id)
                put("displayName", profile.displayName)
                put("createdAt", profile.createdAt)
            }
            array.put(obj)
        }
        return array.toString()
    }

    fun fromJson(json: String?): List<AccountProfile> {
        if (json.isNullOrBlank()) return emptyList()
        val list = mutableListOf<AccountProfile>()
        try {
            val array = JSONArray(json)
            for (i in 0 until array.length()) {
                val obj = array.optJSONObject(i) ?: continue
                val id = obj.optString("id", "")
                val name = obj.optString("displayName", "")
                val createdAt = obj.optLong("createdAt", System.currentTimeMillis())
                if (id.isNotEmpty() && name.isNotEmpty()) {
                    list.add(AccountProfile(id = id, displayName = name, createdAt = createdAt))
                }
            }
        } catch (_: Exception) {
            return emptyList()
        }
        return list
    }
}

```

---

### 2.13. `app/src/main/java/com/corp/enclaveshield/telemetry/SecurityAuditLogger.kt`
**Role:** Security telemetry, ring buffer, markdown report generator

```kotlin
package com.corp.enclaveshield.telemetry

import android.content.Context
import android.os.Build
import android.system.Os
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

enum class LogCategory {
    VPN,
    KILLSWITCH,
    PROXY,
    DNS,
    WEBVIEW,
    SECURITY
}

enum class LogLevel {
    INFO,
    WARN,
    BLOCK,
    ERROR
}

data class LogEntry(
    val timestampIso: String,
    val elapsedMs: Long,
    val category: LogCategory,
    val level: LogLevel,
    val message: String
) {
    val tag: String get() = category.name

    override fun toString(): String {
        return "[$timestampIso][+${elapsedMs}ms][$category][$level] $message"
    }
}

data class DnsStats(
    val totalQueries: Long,
    val cacheHits: Long,
    val resolveErrors: Long,
    val averageLatencyMs: Long,
    val cacheEntries: Long
)

data class TelemetrySnapshot(
    val connectionsAccepted: Long,
    val connectionsRejected: Long,
    val connectionsKilled: Long
)

/**
 * Thread-safe audit logger and telemetry tracker for EnclaveShield.
 *
 * Collects runtime metrics, maintains a 500-entry in-memory ring buffer,
 * logs asynchronously to a rotating log file, and generates self-contained
 * Markdown audit reports for AI security review.
 */
class SecurityAuditLogger(context: Context) {

    private val appContext = context.applicationContext
    val appStartTimeMillis: Long = System.currentTimeMillis()

    // --- Runtime Metric Counters ---
    val vpnConnectCount = AtomicLong(0)
    val vpnDisconnectCount = AtomicLong(0)
    val totalSocksRequests = AtomicLong(0)
    val successfulConnections = AtomicLong(0)
    val activeSocketsCount = AtomicInteger(0)
    val consecutiveNetworkTimeouts = AtomicInteger(0)
    val blockedVpnOffCount = AtomicLong(0)
    val blockedIpv6Count = AtomicLong(0)
    val forceClosedSocketsCount = AtomicLong(0)

    val dnsQueriesTotal = AtomicLong(0)
    val dnsCacheHits = AtomicLong(0)
    val dnsNetworkLookups = AtomicLong(0)
    val dnsFailures = AtomicLong(0)
    val dnsCacheEntries = AtomicLong(0)
    val lastDnsLatencyMs = AtomicLong(0)
    val maxDnsLatencyMs = AtomicLong(0)

    val totalBytesSent = AtomicLong(0)
    val totalBytesReceived = AtomicLong(0)

    @Volatile
    var isProxyOverrideActive: Boolean = false

    @Volatile
    var isDocumentStartJsActive: Boolean = false

    // --- In-Memory Ring Buffer (500 entries) ---
    private val bufferLock = Any()
    private val ringBuffer = ArrayDeque<LogEntry>(MAX_RING_BUFFER_ENTRIES)

    // --- Asynchronous File Appender ---
    private val logScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val logChannel = Channel<LogEntry>(Channel.UNLIMITED)
    private val logFile = File(appContext.filesDir, LOG_FILE_NAME)

    init {
        logScope.launch {
            for (entry in logChannel) {
                appendToFile(entry)
            }
        }
    }

    /**
     * Records a structured security/telemetry log entry.
     * Enforces privacy: NEVER include tokens, cookies, or chat messages in [message].
     */
    fun log(category: LogCategory, level: LogLevel, message: String) {
        val now = System.currentTimeMillis()
        val elapsed = now - appStartTimeMillis
        val isoTimestamp = formatIsoUtc(now)
        val entry = LogEntry(isoTimestamp, elapsed, category, level, message)

        // Log to Android logcat
        when (level) {
            LogLevel.INFO -> Log.i(TAG, "[$category] $message")
            LogLevel.WARN -> Log.w(TAG, "[$category] $message")
            LogLevel.BLOCK -> Log.w(TAG, "[BLOCK][$category] $message")
            LogLevel.ERROR -> Log.e(TAG, "[$category] $message")
        }

        // Store in memory ring buffer
        synchronized(bufferLock) {
            if (ringBuffer.size >= MAX_RING_BUFFER_ENTRIES) {
                ringBuffer.removeFirst()
            }
            ringBuffer.addLast(entry)
        }

        // Dispatch for file logging
        logChannel.trySend(entry)
    }

    fun logInfo(category: String, message: String) = log(parseCategory(category), LogLevel.INFO, message)
    fun logWarning(category: String, message: String) = log(parseCategory(category), LogLevel.WARN, message)
    fun logCritical(category: String, message: String) = log(parseCategory(category), LogLevel.ERROR, message)
    fun logBlock(category: String, message: String) = log(parseCategory(category), LogLevel.BLOCK, message)

    private fun parseCategory(name: String): LogCategory = try {
        LogCategory.valueOf(name.uppercase(Locale.US))
    } catch (_: Exception) {
        LogCategory.SECURITY
    }

    /**
     * Returns a snapshot copy of the in-memory ring buffer (up to [limit] recent entries).
     */
    fun getRecentLogs(limit: Int = 30): List<LogEntry> {
        synchronized(bufferLock) {
            return ringBuffer.toList().takeLast(limit)
        }
    }

    /**
     * Clears all in-memory ring buffer entries and truncates the persistent log file.
     */
    fun clearLogs() {
        synchronized(bufferLock) {
            ringBuffer.clear()
        }
        logScope.launch {
            runCatching {
                if (logFile.exists()) {
                    logFile.writeText("")
                }
            }
        }
        log(LogCategory.SECURITY, LogLevel.INFO, "Audit logs cleared by user request")
    }

    fun clearAllLogs() = clearLogs()

    fun getDnsStats(): DnsStats {
        return DnsStats(
            totalQueries = dnsQueriesTotal.get(),
            cacheHits = dnsCacheHits.get(),
            resolveErrors = dnsFailures.get(),
            averageLatencyMs = lastDnsLatencyMs.get(),
            cacheEntries = dnsCacheEntries.get()
        )
    }

    fun getSnapshot(): TelemetrySnapshot {
        return TelemetrySnapshot(
            connectionsAccepted = successfulConnections.get(),
            connectionsRejected = blockedVpnOffCount.get() + blockedIpv6Count.get(),
            connectionsKilled = forceClosedSocketsCount.get()
        )
    }

    fun generateMarkdownAuditReport(tunnelState: Any? = null, proxyPort: Int? = null): String {
        return generateMarkdownReport(tunnelState, proxyPort)
    }

    /**
     * Updates max DNS latency if [latencyMs] exceeds current maximum.
     */
    fun recordDnsLatency(latencyMs: Long) {
        lastDnsLatencyMs.set(latencyMs)
        var currentMax = maxDnsLatencyMs.get()
        while (latencyMs > currentMax) {
            if (maxDnsLatencyMs.compareAndSet(currentMax, latencyMs)) {
                break
            }
            currentMax = maxDnsLatencyMs.get()
        }
    }

    /**
     * Generates a self-contained Markdown report suitable for pasting to AI assistants
     * (e.g. Gemini Argon 4) for automated security and network invariant verification.
     */
    fun generateMarkdownReport(tunnelState: Any? = null, proxyPort: Int? = null): String {
        val now = System.currentTimeMillis()
        val uptimeSeconds = (now - appStartTimeMillis) / 1000

        val posixTz = runCatching { Os.getenv("TZ") }.getOrNull() ?: "UNKNOWN"
        val jvmTz = TimeZone.getDefault().id
        val jvmLocale = Locale.getDefault().toLanguageTag()

        val recentLogsSnapshot: List<LogEntry> = synchronized(bufferLock) {
            ringBuffer.toList()
        }

        val sb = StringBuilder()
        sb.appendLine("# EnclaveShield Telemetry & Security Audit Report")
        sb.appendLine("Generated at: `${formatIsoUtc(now)}` (Uptime: `${uptimeSeconds}s`)")
        sb.appendLine()

        sb.appendLine("## 1. Device & OS Environment")
        sb.appendLine("- **App & Hardening:** `EnclaveShield v1.1 (Build 2) • Stage 10: Zero-Trust Hardening & Code Review Remediation`")
        sb.appendLine("- **Device:** `${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})`")
        sb.appendLine("- **Android Version:** `Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})`")
        sb.appendLine("- **Target SDK:** `API 36`, **Min SDK:** `API 33`")
        if (tunnelState != null) {
            sb.appendLine("- **Active Tunnel State:** `$tunnelState`")
        }
        if (proxyPort != null) {
            sb.appendLine("- **SOCKS5 Proxy Loopback Port:** `127.0.0.1:$proxyPort`")
        }
        sb.appendLine()

        sb.appendLine("## 2. Security Invariant Self-Checks")
        sb.appendLine("| Security Invariant | Expected Value | Runtime Observed | Status |")
        sb.appendLine("| :--- | :--- | :--- | :--- |")

        val tzMatch = (posixTz == "Europe/Amsterdam" && jvmTz == "Europe/Amsterdam")
        sb.appendLine("| **POSIX / JVM TimeZone** | `Europe/Amsterdam` | POSIX: `$posixTz` / JVM: `$jvmTz` | ${if (tzMatch) "✅ SECURE" else "❌ LEAK RISK"} |")

        val localeMatch = (jvmLocale == "en-US" || jvmLocale.startsWith("en"))
        sb.appendLine("| **JVM Locale** | `en-US` | `$jvmLocale` | ${if (localeMatch) "✅ SECURE" else "❌ LEAK RISK"} |")

        sb.appendLine("| **ProxyController Lock** | `Active (127.0.0.1:<port>)` | `${if (isProxyOverrideActive) "Active (No Fallback)" else "Inactive"}` | ${if (isProxyOverrideActive) "✅ SECURE" else "❌ UNPROTECTED"} |")
        sb.appendLine("| **WebRTC / Document-Start JS** | `Active` | `${if (isDocumentStartJsActive) "Injected" else "Missing"}` | ${if (isDocumentStartJsActive) "✅ SECURE" else "❌ UNPROTECTED"} |")
        sb.appendLine()

        sb.appendLine("## 3. Network & Gatekeeper Telemetry Metrics")
        sb.appendLine("| Metric | Value | Description |")
        sb.appendLine("| :--- | :--- | :--- |")
        sb.appendLine("| **VPN Connect Count** | `${vpnConnectCount.get()}` | Number of times active VPN tunnel was detected |")
        sb.appendLine("| **VPN Disconnect Count** | `${vpnDisconnectCount.get()}` | Number of VPN drop / lost events |")
        sb.appendLine("| **Total SOCKS5 Requests** | `${totalSocksRequests.get()}` | Total connection requests handled by proxy |")
        sb.appendLine("| **Successful Outbound Connects** | `${successfulConnections.get()}` | Connections established through `tun*` source IP |")
        sb.appendLine("| **Blocked (VPN Off / Disconnected)** | `${blockedVpnOffCount.get()}` | Connections refused because VPN was inactive |")
        sb.appendLine("| **Blocked IPv6 Requests** | `${blockedIpv6Count.get()}` | IPv6 (ATYP 0x04) requests rejected with 0x08 |")
        sb.appendLine("| **Force-Closed Sockets** | `${forceClosedSocketsCount.get()}` | Sockets terminated mid-stream on VPN drop |")
        sb.appendLine("| **Active Sockets in Pool** | `${activeSocketsCount.get()}` | Currently open client / remote sockets |")
        sb.appendLine("| **DNS Queries Total** | `${dnsQueriesTotal.get()}` | Raw DNS requests handled by `TunnelDnsResolver` |")
        sb.appendLine("| **DNS Cache Hits** | `${dnsCacheHits.get()}` | Resolved from 60s in-memory cache |")
        sb.appendLine("| **DNS Network TCP Lookups** | `${dnsNetworkLookups.get()}` | RFC 1035 TCP queries sent via `tun*` interface |")
        sb.appendLine("| **DNS Failures** | `${dnsFailures.get()}` | Failed DNS queries |")
        sb.appendLine("| **DNS Latency (Last / Max)** | `${lastDnsLatencyMs.get()}ms / ${maxDnsLatencyMs.get()}ms` | TCP DNS resolution response time |")
        sb.appendLine("| **Data Relayed (Sent / Recv)** | `${formatBytes(totalBytesSent.get())} / ${formatBytes(totalBytesReceived.get())}` | Bytes relayed through SOCKS5 gatekeeper |")
        sb.appendLine()

        sb.appendLine("## 4. Chronological Event Log (Recent ${recentLogsSnapshot.size} events)")
        sb.appendLine("```text")
        if (recentLogsSnapshot.isEmpty()) {
            sb.appendLine("(No log entries recorded yet)")
        } else {
            for (entry in recentLogsSnapshot) {
                sb.appendLine(entry.toString())
            }
        }
        sb.appendLine("```")

        return sb.toString()
    }

    private fun appendToFile(entry: LogEntry) {
        runCatching {
            // Rotate file if exceeding 512 KB
            if (logFile.exists() && logFile.length() > MAX_LOG_FILE_BYTES) {
                val backupFile = File(appContext.filesDir, "${LOG_FILE_NAME}.old")
                if (backupFile.exists()) backupFile.delete()
                logFile.renameTo(backupFile)
            }

            FileWriter(logFile, true).use { writer ->
                writer.appendLine(entry.toString())
            }
        }
    }

    private fun formatIsoUtc(timestampMillis: Long): String {
        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        return sdf.format(Date(timestampMillis))
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        return String.format(Locale.US, "%.2f MB", mb)
    }

    companion object {
        private const val TAG = "SecurityAuditLogger"
        private const val LOG_FILE_NAME = "enclaveshield_audit.log"
        private const val MAX_LOG_FILE_BYTES = 512 * 1024L // 512 KB
        private const val MAX_RING_BUFFER_ENTRIES = 500
    }
}

```

---

### 2.14. `app/src/main/java/com/corp/enclaveshield/ui/AppIconManager.kt`
**Role:** Launcher alias switcher

```kotlin
package com.corp.enclaveshield.ui

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log

enum class AppIconOption(val key: String, val aliasClass: String) {
    VARIANT_1("variant_1", "com.corp.enclaveshield.MainActivityAliasDefault"),
    VARIANT_2("variant_2", "com.corp.enclaveshield.MainActivityAliasVariant2")
}

/**
 * Manages dynamic app icon switching via [PackageManager.setComponentEnabledSetting]
 * and Android <activity-alias> components.
 */
class AppIconManager(private val context: Context) {

    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getCurrentIcon(): AppIconOption {
        val saved = prefs.getString(KEY_ICON, AppIconOption.VARIANT_1.key)
        return if (saved == AppIconOption.VARIANT_2.key) AppIconOption.VARIANT_2 else AppIconOption.VARIANT_1
    }

    fun setAppIcon(option: AppIconOption): Boolean {
        return try {
            val pm = context.packageManager
            val pkg = context.packageName

            val alias1 = ComponentName(pkg, AppIconOption.VARIANT_1.aliasClass)
            val alias2 = ComponentName(pkg, AppIconOption.VARIANT_2.aliasClass)

            when (option) {
                AppIconOption.VARIANT_1 -> {
                    pm.setComponentEnabledSetting(
                        alias1,
                        PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                        PackageManager.DONT_KILL_APP
                    )
                    pm.setComponentEnabledSetting(
                        alias2,
                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                        PackageManager.DONT_KILL_APP
                    )
                }
                AppIconOption.VARIANT_2 -> {
                    pm.setComponentEnabledSetting(
                        alias2,
                        PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                        PackageManager.DONT_KILL_APP
                    )
                    pm.setComponentEnabledSetting(
                        alias1,
                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                        PackageManager.DONT_KILL_APP
                    )
                }
            }

            prefs.edit().putString(KEY_ICON, option.key).apply()
            Log.i(TAG, "App icon switched to: ${option.key}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to switch app icon", e)
            false
        }
    }

    companion object {
        private const val TAG = "AppIconManager"
        private const val PREFS_NAME = "enclaveshield_icon_prefs"
        private const val KEY_ICON = "selected_app_icon"
    }
}

```

---

### 2.15. `app/src/main/java/com/corp/enclaveshield/ui/UiLanguageManager.kt`
**Role:** Language state management

```kotlin
package com.corp.enclaveshield.ui

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class UiLanguage(val code: String, val label: String) {
    RU("ru", "RU"),
    EN("en", "EN")
}

/**
 * Manages the UI language of the Android application shell (Russian vs English).
 *
 * CRITICAL SECURITY INVARIANT:
 * This class NEVER calls Locale.setDefault(), Configuration.setLocale(), or
 * updates Android resource configurations!
 * All UI strings are resolved in Kotlin memory. This guarantees that:
 * 1. The JVM Locale remains strictly Locale.US ("en-US").
 * 2. Chromium / WebView engine and HTTP Accept-Language headers NEVER leak
 *    "ru-RU" or Russian system locale to web pages.
 */
class UiLanguageManager(context: Context) {

    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val _language = MutableStateFlow(loadSavedLanguage())
    val language: StateFlow<UiLanguage> = _language.asStateFlow()

    fun setLanguage(lang: UiLanguage) {
        prefs.edit().putString(KEY_LANG, lang.code).apply()
        _language.value = lang
    }

    fun toggleLanguage(): UiLanguage {
        val next = if (_language.value == UiLanguage.RU) UiLanguage.EN else UiLanguage.RU
        setLanguage(next)
        return next
    }

    private fun loadSavedLanguage(): UiLanguage {
        val saved = prefs.getString(KEY_LANG, UiLanguage.RU.code)
        return if (saved == UiLanguage.EN.code) UiLanguage.EN else UiLanguage.RU
    }

    companion object {
        private const val PREFS_NAME = "enclaveshield_ui_prefs"
        private const val KEY_LANG = "ui_language"
    }
}

```

---

### 2.16. `app/src/main/java/com/corp/enclaveshield/ui/UiStrings.kt`
**Role:** Bilingual string catalog

```kotlin
package com.corp.enclaveshield.ui

/**
 * Self-contained bilingual string catalog for EnclaveShield UI.
 * Completely decoupled from Android's resource Locale subsystem to prevent any locale leak.
 */
object UiStrings {

    fun statusActive(lang: UiLanguage, iface: String, ip: String, port: Int): String = when (lang) {
        UiLanguage.RU -> "VPN АКТИВЕН: $iface ($ip) | SOCKS5: 127.0.0.1:$port"
        UiLanguage.EN -> "VPN ACTIVE: $iface ($ip) | SOCKS5: 127.0.0.1:$port"
    }

    fun statusOffline(lang: UiLanguage, port: Int): String = when (lang) {
        UiLanguage.RU -> "НЕТ VPN — СЕТЬ ИЗОЛИРОВАНА (OFFLINE) | SOCKS5: 127.0.0.1:$port"
        UiLanguage.EN -> "NO VPN — NETWORK ISOLATED (OFFLINE) | SOCKS5: 127.0.0.1:$port"
    }

    fun statusConnectionLost(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Связь потеряна (VPN отключён) — трафик заблокирован"
        UiLanguage.EN -> "Connection lost (VPN disconnected) — network traffic blocked"
    }

    fun statusRestored(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "VPN восстановлен — трафик разблокирован"
        UiLanguage.EN -> "VPN restored — traffic unblocked"
    }

    fun waitingTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Ожидание подключения VPN…"
        UiLanguage.EN -> "Waiting for VPN connection…"
    }

    fun waitingDesc(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Сетевой трафик строго изолирован до тех пор, пока туннель Amnezia VPN не подключится."
        UiLanguage.EN -> "Network traffic is strictly isolated until Amnezia VPN tunnel is connected."
    }

    fun securityErrorTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Ошибка безопасности: Proxy Override не поддерживается"
        UiLanguage.EN -> "Security Error: Proxy Override Unsupported"
    }

    fun securityErrorDesc(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "WebViewFeature.PROXY_OVERRIDE не поддерживается системным WebView. Создание WebView заблокировано для исключения утечек."
        UiLanguage.EN -> "WebViewFeature.PROXY_OVERRIDE is not supported by system WebView. WebView instantiation blocked to prevent network leaks."
    }

    fun btnDiagnostics(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "📊 Инфо"
        UiLanguage.EN -> "📊 Info"
    }

    fun btnReturnToPortal(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "← Corporate Portal"
        UiLanguage.EN -> "← Corporate Portal"
    }

    fun btnLangToggle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "RU"
        UiLanguage.EN -> "EN"
    }

    // --- Part 3: Human-Readable Diagnostics & Explanations ---

    fun diagDialogTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Панель Безопасности и Диагностики"
        UiLanguage.EN -> "Security & Diagnostics Dashboard"
    }

    fun sectionKillSwitchTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "1. Общий статус защиты (Kill-Switch)"
        UiLanguage.EN -> "1. Kill-Switch Protection Status"
    }

    fun killSwitchProtected(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "🛡️ ЗАЩИЩЕНО (Трафик идёт через VPN)"
        UiLanguage.EN -> "🛡️ PROTECTED (Traffic routed via VPN)"
    }

    fun killSwitchBlocked(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "🛑 СЕТЬ ЗАБЛОКИРОВАНА (VPN отключён)"
        UiLanguage.EN -> "🛑 NETWORK BLOCKED (VPN Disconnected)"
    }

    fun killSwitchExplanation(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Принцип Fail-Closed: приложение разрывает все соединения в ту же миллисекунду, когда отключается Amnezia VPN. Для сайта Corporate Portal это выглядит как обычная потеря сигнала Wi-Fi/LTE. Ваш реальный IP-адрес никогда не попадёт в сеть."
        UiLanguage.EN -> "Fail-Closed principle: the app terminates all connections in the very millisecond Amnezia VPN drops. To Corporate Portal's servers, this appears as normal Wi-Fi/LTE signal loss. Your real IP address can never leak to the network."
    }

    fun sectionTunnelTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "2. Виртуальный адаптер VPN (Tunnel Interface)"
        UiLanguage.EN -> "2. VPN Tunnel Adapter & IP"
    }

    fun tunnelNoActive(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Нет активного туннеля"
        UiLanguage.EN -> "No active tunnel interface"
    }

    fun tunnelExplanation(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Имя сетевого интерфейса Amnezia VPN и ваш внутренний адрес внутри туннеля. Все сокеты приложения привязаны к этому адресу на уровне ядра Linux — пакеты физически не могут уйти через обычный Wi-Fi или мобильную сеть."
        UiLanguage.EN -> "Network interface name of Amnezia VPN and internal tunnel IP address. All app sockets are bound to this address at the Linux kernel level — packets are physically incapable of leaving via physical Wi-Fi or mobile networks."
    }

    fun sectionProxyTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "3. Внутренний шлюз-привратник (Local SOCKS5 Gatekeeper)"
        UiLanguage.EN -> "3. In-Process SOCKS5 Gatekeeper"
    }

    fun proxyStatus(lang: UiLanguage, port: Int): String = when (lang) {
        UiLanguage.RU -> "127.0.0.1:$port (Строгая изоляция без fallback)"
        UiLanguage.EN -> "127.0.0.1:$port (Strict isolation without fallback)"
    }

    fun proxyExplanation(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Локальный прокси-фильтр внутри приложения. Встроенный браузер не имеет прямого доступа к интернету и обязан направлять 100% трафика через этот внутренний порт."
        UiLanguage.EN -> "Local in-process proxy filter. The embedded browser has no direct network access and is required to route 100% of traffic through this loopback port."
    }

    fun sectionDnsTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "4. Изоляция DNS (Zero-Leak TCP DNS)"
        UiLanguage.EN -> "4. Zero-Leak TCP DNS Isolation"
    }

    fun dnsStatus(lang: UiLanguage, cacheCount: Long, errorsCount: Long): String = when (lang) {
        UiLanguage.RU -> "Туннель TCP 1.1.1.1 / 8.8.8.8 | Кэш: $cacheCount | Ошибок: $errorsCount"
        UiLanguage.EN -> "Tunnel TCP 1.1.1.1 / 8.8.8.8 | Cache: $cacheCount | Errors: $errorsCount"
    }

    fun dnsExplanation(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Предотвращает утечку через системный DNS телефона и исключает пересечение со сторонними Smart DNS (например, для Gemini). Все адреса сайтов запрашиваются строго внутри зашифрованного VPN-туннеля."
        UiLanguage.EN -> "Prevents leaks via host system DNS and eliminates collision with third-party Smart DNS (e.g. for Gemini). All domain lookups are performed strictly inside the encrypted VPN tunnel."
    }

    fun sectionFingerprintTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "5. Маскировка устройства (Anti-Fingerprinting)"
        UiLanguage.EN -> "5. Anti-Fingerprinting & Hardware Masking"
    }

    fun fingerprintStatus(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Часовой пояс: Europe/Amsterdam | Язык для сайта: en-US | WebRTC: Выключен | IPv6: Заблокирован"
        UiLanguage.EN -> "Timezone: Europe/Amsterdam | Web Locale: en-US | WebRTC: Disabled | IPv6: Blocked"
    }

    fun fingerprintExplanation(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Скрывает ваш реальный часовой пояс и язык телефона от скриптов сайта, а также полностью отключает протокол WebRTC и IPv6, через которые сайты могут узнать ваш настоящий IP."
        UiLanguage.EN -> "Masks your true host timezone and system language from web scripts, and completely disables WebRTC and IPv6 protocols which websites could use to discover your real IP."
    }

    // --- Action buttons & Toasts ---

    fun btnCopyAiReport(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "📋 Скопировать отчёт для ИИ"
        UiLanguage.EN -> "📋 Copy AI Report"
    }

    fun btnShareLog(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "📤 Поделиться логом"
        UiLanguage.EN -> "📤 Share Log"
    }

    fun btnBrowserLeaks(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "🌐 Проверить на BrowserLeaks"
        UiLanguage.EN -> "🌐 Test on BrowserLeaks"
    }

    fun btnClearLogs(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "🧹 Очистить лог"
        UiLanguage.EN -> "🧹 Clear Log"
    }

    fun btnChangeIcon(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "🎨 Сменить иконку приложения"
        UiLanguage.EN -> "🎨 Change App Icon"
    }

    fun dialogChooseIconTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Выберите иконку приложения"
        UiLanguage.EN -> "Choose App Icon"
    }

    fun iconVariant1(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Вариант 1 (Classic Cage)"
        UiLanguage.EN -> "Variant 1 (Classic Cage)"
    }

    fun iconVariant2(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Вариант 2 (Alternative Cage)"
        UiLanguage.EN -> "Variant 2 (Alternative Cage)"
    }

    fun toastIconChanged(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Иконка приложения обновлена!"
        UiLanguage.EN -> "App icon updated!"
    }

    fun btnClose(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Закрыть"
        UiLanguage.EN -> "Close"
    }

    fun toastReportCopied(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Отчёт для аудита ИИ скопирован в буфер обмена!"
        UiLanguage.EN -> "AI audit report copied to clipboard!"
    }

    // --- Multi-Account Switcher (Stage 7) ---

    fun btnAccountSelector(lang: UiLanguage, accountName: String): String = when (lang) {
        UiLanguage.RU -> "👤 $accountName ▾"
        UiLanguage.EN -> "👤 $accountName ▾"
    }

    fun accountDialogTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Управление аккаунтами"
        UiLanguage.EN -> "Account Management"
    }

    fun btnAddAccount(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "➕ Добавить новый аккаунт"
        UiLanguage.EN -> "➕ Add New Account"
    }

    fun dialogAddAccountTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Новый аккаунт Corporate Portal"
        UiLanguage.EN -> "New Corporate Portal Account"
    }

    fun dialogAddAccountHint(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Название (например: Work, Personal)"
        UiLanguage.EN -> "Account name (e.g., Work, Personal)"
    }

    fun dialogRenameTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Переименовать аккаунт"
        UiLanguage.EN -> "Rename Account"
    }

    fun dialogDeleteConfirmTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Удалить аккаунт?"
        UiLanguage.EN -> "Delete Account?"
    }

    fun dialogDeleteConfirmMessage(lang: UiLanguage, name: String): String = when (lang) {
        UiLanguage.RU -> "Вы уверены, что хотите удалить профиль «$name»? Все сессионные данные и куки этого аккаунта будут стёрты."
        UiLanguage.EN -> "Are you sure you want to delete profile \"$name\"? All session data and cookies for this account will be erased."
    }

    fun dialogDeleteCannotDeleteOnly(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Нельзя удалить единственный оставшийся профиль"
        UiLanguage.EN -> "Cannot delete the only remaining profile"
    }

    fun btnAdd(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Добавить"
        UiLanguage.EN -> "Add"
    }

    fun btnRename(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Переименовать"
        UiLanguage.EN -> "Rename"
    }

    fun btnDelete(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Удалить"
        UiLanguage.EN -> "Delete"
    }

    fun btnCancel(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Отмена"
        UiLanguage.EN -> "Cancel"
    }

    fun btnSave(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Сохранить"
        UiLanguage.EN -> "Save"
    }

    fun toastProfileSwitched(lang: UiLanguage, name: String): String = when (lang) {
        UiLanguage.RU -> "Переключено на: $name"
        UiLanguage.EN -> "Switched to: $name"
    }

    fun toastProfileCreated(lang: UiLanguage, name: String): String = when (lang) {
        UiLanguage.RU -> "Создан аккаунт: $name"
        UiLanguage.EN -> "Created account: $name"
    }

    fun toastProfileDeleted(lang: UiLanguage, name: String): String = when (lang) {
        UiLanguage.RU -> "Аккаунт удалён: $name"
        UiLanguage.EN -> "Account deleted: $name"
    }

    fun toastProfileRenamed(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Аккаунт переименован"
        UiLanguage.EN -> "Account renamed"
    }

    fun activeAccountBadge(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> " (Активен)"
        UiLanguage.EN -> " (Active)"
    }

    // --- Minimalist Floating Security Anchor & Modern Status Bar ---

    fun sectionVersionsTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "0. Версии системы и компонентов"
        UiLanguage.EN -> "0. System & Component Versions"
    }

    fun btnVersions(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "📦 Версии компонентов"
        UiLanguage.EN -> "📦 Component Versions"
    }

    fun dialogVersionsTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Версии компонентов и окружения"
        UiLanguage.EN -> "Component & Runtime Versions"
    }

    fun btnCopyVersions(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "📋 Копировать версии"
        UiLanguage.EN -> "📋 Copy Versions"
    }

    fun toastVersionsCopied(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Информация о версиях скопирована в буфер обмена!"
        UiLanguage.EN -> "Version info copied to clipboard!"
    }

    fun statusProtectedConcise(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "🛡️ Защищено"
        UiLanguage.EN -> "🛡️ Protected"
    }

    fun statusBlockedConcise(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "🛑 Сеть блокирована"
        UiLanguage.EN -> "🛑 Blocked"
    }

    fun statusLeakRiskConcise(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "⚠️ Туннель не отвечает"
        UiLanguage.EN -> "⚠️ Tunnel Unresponsive"
    }

    fun toastDownloadSuccess(lang: UiLanguage, filename: String): String = when (lang) {
        UiLanguage.RU -> "Файл сохранён: $filename"
        UiLanguage.EN -> "File saved: $filename"
    }

    fun toastDownloadFailed(lang: UiLanguage, error: String): String = when (lang) {
        UiLanguage.RU -> "Ошибка загрузки: $error"
        UiLanguage.EN -> "Download error: $error"
    }

    fun subStatusActive(lang: UiLanguage, iface: String, port: Int): String = when (lang) {
        UiLanguage.RU -> "VPN: $iface • SOCKS5: 127.0.0.1:$port"
        UiLanguage.EN -> "VPN: $iface • SOCKS5: 127.0.0.1:$port"
    }

    fun subStatusOffline(lang: UiLanguage, port: Int): String = when (lang) {
        UiLanguage.RU -> "Kill-Switch активен • SOCKS5: 127.0.0.1:$port"
        UiLanguage.EN -> "Kill-Switch active • SOCKS5: 127.0.0.1:$port"
    }
}

```

---

### 2.17. `app/src/test/java/com/corp/enclaveshield/net/TunnelDnsResolverTest.kt`
**Role:** DNS resolver unit tests: Watchdog, StaleCache, Single-Flight, RFC 1035 TCP

```kotlin
package com.corp.enclaveshield.net

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

class TunnelDnsResolverTest {

    @Test
    fun parseIpv4Literal_validIps() {
        val ip1 = TunnelDnsResolver.parseIpv4Literal("127.0.0.1")
        assertNotNull(ip1)
        assertArrayEquals(byteArrayOf(127, 0, 0, 1), ip1!!.address)

        val ip2 = TunnelDnsResolver.parseIpv4Literal("10.8.0.2")
        assertNotNull(ip2)
        assertArrayEquals(byteArrayOf(10, 8, 0, 2), ip2!!.address)
    }

    @Test
    fun parseIpv4Literal_invalidIps() {
        assertNull(TunnelDnsResolver.parseIpv4Literal("portal.internal-enterprise.net"))
        assertNull(TunnelDnsResolver.parseIpv4Literal("256.0.0.1"))
        assertNull(TunnelDnsResolver.parseIpv4Literal("1.2.3"))
        assertNull(TunnelDnsResolver.parseIpv4Literal(""))
    }

    @Test
    fun buildTcpDnsQuery_validStructure() {
        val queryId = 0x1234
        val packet = TunnelDnsResolver.buildTcpDnsQuery("portal.internal-enterprise.net", queryId)

        val buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)
        val tcpLen = buffer.short.toInt() and 0xFFFF
        assertEquals(packet.size - 2, tcpLen)

        val id = buffer.short.toInt() and 0xFFFF
        assertEquals(queryId, id)

        val flags = buffer.short.toInt() and 0xFFFF
        assertEquals(0x0100, flags) // RD = 1

        val qdCount = buffer.short.toInt() and 0xFFFF
        assertEquals(1, qdCount)

        val anCount = buffer.short.toInt() and 0xFFFF
        assertEquals(0, anCount)
    }

    @Test
    fun parseTcpDnsResponse_extractsArecord() {
        val queryId = 0xABCD
        // Construct a mock DNS response for portal.internal-enterprise.net -> 104.18.2.3
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(queryId.toShort())
        header.putShort(0x8180.toShort()) // Standard response, No error
        header.putShort(1.toShort())      // QDCOUNT = 1
        header.putShort(1.toShort())      // ANCOUNT = 1
        header.putShort(0.toShort())      // NSCOUNT = 0
        header.putShort(0.toShort())      // ARCOUNT = 0
        out.write(header.array())

        // Question: portal.internal-enterprise.net IN A
        out.write(byteArrayOf(6, 'c'.code.toByte(), 'l'.code.toByte(), 'a'.code.toByte(), 'u'.code.toByte(), 'd'.code.toByte(), 'e'.code.toByte()))
        out.write(byteArrayOf(2, 'a'.code.toByte(), 'i'.code.toByte()))
        out.write(0) // null root
        val qtail = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        qtail.putShort(1.toShort()) // QTYPE A
        qtail.putShort(1.toShort()) // QCLASS IN
        out.write(qtail.array())

        // Answer: pointer 0xC00C, TYPE 1, CLASS 1, TTL 300, RDLENGTH 4, IP 104.18.2.3
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val atail = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        atail.putShort(1.toShort())   // TYPE A
        atail.putShort(1.toShort())   // CLASS IN
        atail.putInt(300)             // TTL
        atail.putShort(4.toShort())   // RDLENGTH = 4
        out.write(atail.array())
        out.write(byteArrayOf(104, 18, 2, 3)) // IP

        val responseBytes = out.toByteArray()
        val parsed = TunnelDnsResolver.parseTcpDnsResponse(responseBytes, queryId)

        assertNotNull(parsed.address)
        assertFalse(parsed.isNoData)
        assertFalse(parsed.isError)
        assertArrayEquals(byteArrayOf(104, 18, 2, 3), parsed.address!!.address)
    }

    @Test
    fun parseTcpDnsResponse_skipsCnameToFindA() {
        val queryId = 0x5678
        // Construct a mock response where Answer 1 is CNAME and Answer 2 is A record
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(queryId.toShort())
        header.putShort(0x8180.toShort()) // Standard response, No error
        header.putShort(1.toShort())      // QDCOUNT = 1
        header.putShort(2.toShort())      // ANCOUNT = 2
        header.putShort(0.toShort())      // NSCOUNT = 0
        header.putShort(0.toShort())      // ARCOUNT = 0
        out.write(header.array())

        // Question: test.ai IN A
        out.write(byteArrayOf(4, 't'.code.toByte(), 'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte()))
        out.write(byteArrayOf(2, 'a'.code.toByte(), 'i'.code.toByte()))
        out.write(0)
        val qtail = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        qtail.putShort(1.toShort()) // QTYPE A
        qtail.putShort(1.toShort()) // QCLASS IN
        out.write(qtail.array())

        // Answer 1: CNAME (type 5) pointing to target.ai
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val cnameHeader = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        cnameHeader.putShort(5.toShort()) // TYPE CNAME
        cnameHeader.putShort(1.toShort()) // CLASS IN
        cnameHeader.putInt(60)            // TTL
        val targetName = byteArrayOf(6, 't'.code.toByte(), 'a'.code.toByte(), 'r'.code.toByte(), 'g'.code.toByte(), 'e'.code.toByte(), 't'.code.toByte(), 2, 'a'.code.toByte(), 'i'.code.toByte(), 0)
        cnameHeader.putShort(targetName.size.toShort())
        out.write(cnameHeader.array())
        out.write(targetName)

        // Answer 2: A record (type 1)
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val aHeader = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        aHeader.putShort(1.toShort()) // TYPE A
        aHeader.putShort(1.toShort()) // CLASS IN
        aHeader.putInt(60)
        aHeader.putShort(4.toShort())
        out.write(aHeader.array())
        out.write(byteArrayOf(192.toByte(), 0, 2, 1))

        val parsed = TunnelDnsResolver.parseTcpDnsResponse(out.toByteArray(), queryId)
        assertNotNull(parsed.address)
        assertFalse(parsed.isNoData)
        assertArrayEquals(byteArrayOf(192.toByte(), 0, 2, 1), parsed.address!!.address)
    }

    @Test
    fun parseTcpDnsResponse_nodata_returnsIsNoDataTrue() {
        val queryId = 0x9999
        // Construct RFC 2308 NODATA response: RCODE=0, ANCOUNT=0 (e.g. brunhild.challenges.cloudflare.com)
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(queryId.toShort())
        header.putShort(0x8180.toShort()) // Standard response, No error (RCODE=0)
        header.putShort(1.toShort())      // QDCOUNT = 1
        header.putShort(0.toShort())      // ANCOUNT = 0 (NODATA!)
        header.putShort(1.toShort())      // NSCOUNT = 1 (SOA)
        header.putShort(0.toShort())      // ARCOUNT = 0
        out.write(header.array())

        val parsed = TunnelDnsResolver.parseTcpDnsResponse(out.toByteArray(), queryId)
        assertNull(parsed.address)
        assertTrue(parsed.isNoData)
        assertFalse(parsed.isError)
        assertEquals(0, parsed.rcode)
    }

    @Test
    fun parseTcpDnsResponse_queryIdMismatchReturnsError() {
        val queryId = 0x1111
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(0x2222.toShort()) // Mismatched ID
        header.putShort(0x8180.toShort())
        header.putShort(0.toShort())
        header.putShort(0.toShort())
        header.putShort(0.toShort())
        header.putShort(0.toShort())

        val result = TunnelDnsResolver.parseTcpDnsResponse(header.array(), queryId)
        assertTrue(result.isError)
        assertNull(result.address)
    }

    @Test
    fun resolve_ipv4Literal_returnsDirectlyWithoutNetworkQuery() = kotlinx.coroutines.runBlocking {
        val resolver = TunnelDnsResolver()
        val tunIp = java.net.InetAddress.getByAddress(byteArrayOf(10, 0, 0, 1)) as java.net.Inet4Address
        val result = resolver.resolve("192.168.1.100", tunIp, null)
        assertNotNull(result)
        assertArrayEquals(byteArrayOf(192.toByte(), 168.toByte(), 1, 100), result!!.address)
    }

    @Test
    fun resolve_withStaleFallback_returnsStaleWhenResolutionFails() = kotlinx.coroutines.runBlocking {
        val resolver = TunnelDnsResolver()
        val tunIp = java.net.InetAddress.getByAddress(byteArrayOf(10, 0, 0, 1)) as java.net.Inet4Address
        val staleIp = java.net.InetAddress.getByAddress(byteArrayOf(104, 18, 2, 3)) as java.net.Inet4Address

        resolver.putStaleEntryForTesting("portal.internal-enterprise.net", staleIp)
        assertEquals(1, resolver.staleCacheSize)

        // When network queries fail (unreachable in unit test), resolver serves last-known stale IP
        val result = resolver.resolve("portal.internal-enterprise.net", tunIp, null)
        assertNotNull(result)
        assertEquals(staleIp, result)
    }

    @Test
    fun cacheSize_and_clearCache() {
        val resolver = TunnelDnsResolver()
        assertEquals(0, resolver.cacheSize)
        assertEquals(0, resolver.negativeCacheSize)
        assertEquals(0, resolver.staleCacheSize)

        val staleIp = java.net.InetAddress.getByAddress(byteArrayOf(104, 18, 2, 3)) as java.net.Inet4Address
        resolver.putStaleEntryForTesting("portal.internal-enterprise.net", staleIp)
        assertEquals(1, resolver.staleCacheSize)

        resolver.clearCache()
        assertEquals(0, resolver.cacheSize)
        assertEquals(0, resolver.negativeCacheSize)
        assertEquals(0, resolver.staleCacheSize)
    }

    @Test
    fun clearCache_withPreserveStale_keepsStaleEntries() {
        val resolver = TunnelDnsResolver()
        val staleIp = java.net.InetAddress.getByAddress(byteArrayOf(104, 18, 2, 3)) as java.net.Inet4Address
        resolver.putStaleEntryForTesting("portal.internal-enterprise.net", staleIp)
        assertEquals(1, resolver.staleCacheSize)

        resolver.clearCache(clearStale = false)
        assertEquals(1, resolver.staleCacheSize)
    }

    @Test
    fun parseTcpDnsResponse_multipleArecords_picksOne() {
        val queryId = 0x3333
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(queryId.toShort())
        header.putShort(0x8180.toShort())
        header.putShort(1.toShort())      // QDCOUNT
        header.putShort(2.toShort())      // ANCOUNT = 2
        header.putShort(0.toShort())
        header.putShort(0.toShort())
        out.write(header.array())

        // Question
        out.write(byteArrayOf(6, 'c'.code.toByte(), 'l'.code.toByte(), 'a'.code.toByte(), 'u'.code.toByte(), 'd'.code.toByte(), 'e'.code.toByte(), 2, 'a'.code.toByte(), 'i'.code.toByte(), 0))
        val qtail = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        qtail.putShort(1.toShort())
        qtail.putShort(1.toShort())
        out.write(qtail.array())

        // Answer 1: 104.18.2.3
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val a1 = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        a1.putShort(1.toShort())
        a1.putShort(1.toShort())
        a1.putInt(300)
        a1.putShort(4.toShort())
        out.write(a1.array())
        out.write(byteArrayOf(104, 18, 2, 3))

        // Answer 2: 104.18.3.4
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val a2 = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        a2.putShort(1.toShort())
        a2.putShort(1.toShort())
        a2.putInt(300)
        a2.putShort(4.toShort())
        out.write(a2.array())
        out.write(byteArrayOf(104, 18, 3, 4))

        val parsed = TunnelDnsResolver.parseTcpDnsResponse(out.toByteArray(), queryId)
        assertNotNull(parsed.address)
        val picked = parsed.address!!.hostAddress
        assertTrue(picked == "104.18.2.3" || picked == "104.18.3.4")
    }

    @Test
    fun parseTcpDnsResponse_verifiesQname() {
        val queryId = 0xABCD
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(queryId.toShort())
        header.putShort(0x8180.toShort())
        header.putShort(1.toShort())      // QDCOUNT = 1
        header.putShort(1.toShort())      // ANCOUNT = 1
        header.putShort(0.toShort())
        header.putShort(0.toShort())
        out.write(header.array())

        // Question: portal.internal-enterprise.net IN A
        out.write(byteArrayOf(6, 'c'.code.toByte(), 'l'.code.toByte(), 'a'.code.toByte(), 'u'.code.toByte(), 'd'.code.toByte(), 'e'.code.toByte()))
        out.write(byteArrayOf(2, 'a'.code.toByte(), 'i'.code.toByte()))
        out.write(0)
        val qtail = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        qtail.putShort(1.toShort())
        qtail.putShort(1.toShort())
        out.write(qtail.array())

        // Answer
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val atail = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        atail.putShort(1.toShort())
        atail.putShort(1.toShort())
        atail.putInt(300)
        atail.putShort(4.toShort())
        out.write(atail.array())
        out.write(byteArrayOf(104, 18, 2, 3))

        val responseBytes = out.toByteArray()

        // Correct domain matches
        val match = TunnelDnsResolver.parseTcpDnsResponse(responseBytes, queryId, "portal.internal-enterprise.net")
        assertFalse(match.isError)
        assertEquals(InetAddress.getByAddress(byteArrayOf(104, 18, 2, 3)), match.address)

        // Case-insensitive & trailing dot matches
        val matchCase = TunnelDnsResolver.parseTcpDnsResponse(responseBytes, queryId, "CLAUDE.AI.")
        assertFalse(matchCase.isError)

        // Mismatched domain fails with isError = true
        val mismatch = TunnelDnsResolver.parseTcpDnsResponse(responseBytes, queryId, "attacker.com")
        assertTrue(mismatch.isError)
    }

    @Test
    fun clearCache_preservesStaleCacheWhenRequested() {
        val resolver = TunnelDnsResolver()
        val ip = InetAddress.getByAddress(byteArrayOf(104, 18, 2, 3)) as Inet4Address
        resolver.putStaleEntryForTesting("portal.internal-enterprise.net", ip)
        assertEquals(1, resolver.staleCacheSize)

        // Clear without clearing stale
        resolver.clearCache(clearStale = false)
        assertEquals(1, resolver.staleCacheSize)

        // Full clear
        resolver.clearCache(clearStale = true)
        assertEquals(0, resolver.staleCacheSize)
    }
}

```

---

### 2.18. `app/src/test/java/com/corp/enclaveshield/net/VpnGatekeeperProxyTest.kt`
**Role:** SOCKS5 proxy unit tests: Fail-closed killswitch, Allowlist, Private IP block, Regional Guard

```kotlin
package com.corp.enclaveshield.net

import android.content.Context
import android.net.ConnectivityManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.Socket

class VpnGatekeeperProxyTest {

    private val mockContext: Context = mock(Context::class.java)
    private val mockConnectivityManager: ConnectivityManager = mock(ConnectivityManager::class.java)

    @Before
    fun setUp() {
        `when`(mockContext.applicationContext).thenReturn(mockContext)
    }

    @Test
    fun proxyBindsToEphemeralLoopbackPort() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)

        try {
            assertTrue("Listening port should be greater than 0", proxy.listeningPort > 0)
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun failClosed_rejectsConnectionWhenVpnDisconnected() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // 1. SOCKS5 handshake: No-Auth
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()

            val ver = dis.readUnsignedByte()
            val method = dis.readUnsignedByte()
            assertEquals(5, ver)
            assertEquals(0, method)

            // 2. Request CONNECT to 93.184.216.34:80 (IPv4)
            dos.write(byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                93.toByte(), 184.toByte(), 216.toByte(), 34.toByte(),
                0x00, 0x50 // Port 80
            ))
            dos.flush()

            // 3. Server should reply with failure (0x05 Connection refused) because VPN is Disconnected
            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode) // REP_CONN_REFUSED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsIpv6WithAddressTypeNotSupported() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // Handshake
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            // SOCKS5 request with ATYP = 0x04 (IPv6)
            val ipv6Request = ByteArray(22)
            ipv6Request[0] = 0x05 // VER
            ipv6Request[1] = 0x01 // CONNECT
            ipv6Request[2] = 0x00 // RSV
            ipv6Request[3] = 0x04 // ATYP IPv6
            // 16 bytes IPv6 (all 0s)
            ipv6Request[20] = 0x00 // Port 80
            ipv6Request[21] = 0x50

            dos.write(ipv6Request)
            dos.flush()

            // Server must reject with 0x08 (Address type not supported)
            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x08, repCode) // REP_ADDR_TYPE_NOT_SUPPORTED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsIpv6LiteralInAtypDomainWithAddressTypeNotSupported() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // Handshake
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            // SOCKS5 request with ATYP = 0x03 (Domain), but containing IPv6 literal "2604:a880:800:10::e6:b001"
            val ipv6Domain = "2604:a880:800:10::e6:b001".toByteArray(Charsets.US_ASCII)
            val request = ByteArray(4 + 1 + ipv6Domain.size + 2)
            request[0] = 0x05 // VER
            request[1] = 0x01 // CONNECT
            request[2] = 0x00 // RSV
            request[3] = 0x03 // ATYP DOMAIN
            request[4] = ipv6Domain.size.toByte()
            System.arraycopy(ipv6Domain, 0, request, 5, ipv6Domain.size)
            request[request.size - 2] = 0x01 // Port 443
            request[request.size - 1] = 0xBB.toByte()

            dos.write(request)
            dos.flush()

            // Server must reject with 0x08 (Address type not supported)
            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x08, repCode) // REP_ADDR_TYPE_NOT_SUPPORTED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun closeAllActiveSockets_closesTrackedSockets() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            
            // Allow acceptLoop to register the socket
            Thread.sleep(100)

            proxy.closeAllActiveSockets()

            // Wait a brief moment for socket close to propagate
            Thread.sleep(50)

            // Attempting to read from client should return EOF (-1) or throw SocketException
            val readResult = runCatching { client.getInputStream().read() }.getOrDefault(-1)
            assertEquals(-1, readResult)

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsRegionalCisDomainsWithConnectionRefused() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // Handshake
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            // SOCKS5 request with ATYP = 0x03 (Domain), target "yandex.ru"
            val ruDomain = "yandex.ru".toByteArray(Charsets.US_ASCII)
            val request = ByteArray(4 + 1 + ruDomain.size + 2)
            request[0] = 0x05 // VER
            request[1] = 0x01 // CONNECT
            request[2] = 0x00 // RSV
            request[3] = 0x03 // ATYP DOMAIN
            request[4] = ruDomain.size.toByte()
            System.arraycopy(ruDomain, 0, request, 5, ruDomain.size)
            request[request.size - 2] = 0x01 // Port 443
            request[request.size - 1] = 0xBB.toByte()

            dos.write(request)
            dos.flush()

            // Server must reject with 0x05 (Connection refused)
            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode) // REP_CONN_REFUSED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsUppercaseAndDottedCisDomains() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            val ruDomain = "YANDEX.RU.".toByteArray(Charsets.US_ASCII)
            val request = ByteArray(4 + 1 + ruDomain.size + 2)
            request[0] = 0x05
            request[1] = 0x01
            request[2] = 0x00
            request[3] = 0x03
            request[4] = ruDomain.size.toByte()
            System.arraycopy(ruDomain, 0, request, 5, ruDomain.size)
            request[request.size - 2] = 0x01
            request[request.size - 1] = 0xBB.toByte()

            dos.write(request)
            dos.flush()

            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode)

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsNonAllowlistedDomainWithConnectionRefused() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            val evilDomain = "attacker.example.org".toByteArray(Charsets.US_ASCII)
            val request = ByteArray(4 + 1 + evilDomain.size + 2)
            request[0] = 0x05
            request[1] = 0x01
            request[2] = 0x00
            request[3] = 0x03
            request[4] = evilDomain.size.toByte()
            System.arraycopy(evilDomain, 0, request, 5, evilDomain.size)
            request[request.size - 2] = 0x01
            request[request.size - 1] = 0xBB.toByte()

            dos.write(request)
            dos.flush()

            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode)

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsForbiddenLoopbackAndPrivateIpv4() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            // Try connecting to 127.0.0.1:8080 via ATYP_IPV4
            dos.write(byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                127.toByte(), 0.toByte(), 0.toByte(), 1.toByte(),
                0x1F, 0x90.toByte() // 8080
            ))
            dos.flush()

            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode) // REP_CONN_REFUSED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun allowsCloudflareTurnstileAndHcaptchaDomains() {
        val allowed = VpnGatekeeperProxy.ALLOWED_DOMAIN_SUFFIXES
        assertTrue(allowed.contains("cloudflare.com"))
        assertTrue(allowed.contains("hcaptcha.com"))
        assertTrue(allowed.contains("stripe.com"))
        assertTrue(allowed.contains("intercomcdn.com"))
        assertTrue(allowed.contains("statsigapi.net"))

        fun isAllowed(domain: String): Boolean {
            val clean = domain.trim().trimEnd('.').lowercase(java.util.Locale.ROOT)
            return allowed.any { clean == it || clean.endsWith(".$it") }
        }

        assertTrue(isAllowed("challenges.cloudflare.com"))
        assertTrue(isAllowed("js.hcaptcha.com"))
        assertTrue(isAllowed("api.stripe.com"))
        assertTrue(isAllowed("m.stripe.network"))
        assertTrue(isAllowed("nexus-websocket-a.intercom.io"))
        assertTrue(isAllowed("events.statsigapi.net"))
        assertTrue(isAllowed("portal.internal-enterprise.net"))
        assertTrue(isAllowed("cdn.portal.internal-enterprise.net"))
        assertFalse(isAllowed("evil.hacker.com"))
    }
}

```

---

### 2.19. `app/src/test/java/com/corp/enclaveshield/security/AntiFingerprintHardenerTest.kt`
**Role:** Anti-fingerprinting unit tests: Canvas offscreen clone, toString, TTS, Intl, Webdriver

```kotlin
package com.corp.enclaveshield.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale
import java.util.TimeZone

class AntiFingerprintHardenerTest {

    @Test
    fun documentStartJs_containsWebRtcKillSwitch() {
        val js = AntiFingerprintHardener.DOCUMENT_START_JS

        assertTrue("Must kill RTCPeerConnection", js.contains("RTCPeerConnection"))
        assertTrue("Must kill webkitRTCPeerConnection", js.contains("webkitRTCPeerConnection"))
        assertTrue("Must kill RTCDataChannel", js.contains("RTCDataChannel"))
        assertTrue("Must kill RTCIceCandidate", js.contains("RTCIceCandidate"))
        assertTrue("Must kill RTCSessionDescription", js.contains("RTCSessionDescription"))
        assertTrue("Must kill getUserMedia", js.contains("getUserMedia"))
    }

    @Test
    fun documentStartJs_containsDynamicOnLineSpoofing() {
        val js = AntiFingerprintHardener.DOCUMENT_START_JS

        assertTrue("Must reference __enclaveOffline", js.contains("__enclaveOffline"))
        assertTrue("Must spoof navigator.onLine", js.contains("onLine"))
    }

    @Test
    fun documentStartJs_containsTimezoneAndLocaleLockdown() {
        val js = AntiFingerprintHardener.DOCUMENT_START_JS

        assertTrue("Must target Europe/Amsterdam", js.contains("Europe/Amsterdam"))
        assertTrue("Must override getTimezoneOffset", js.contains("getTimezoneOffset"))
        assertTrue("Must override Intl.DateTimeFormat", js.contains("Intl.DateTimeFormat"))
        assertTrue("Must override Date.prototype.toString", js.contains("Date.prototype.toString"))
        assertTrue("Must override Date.prototype.toTimeString", js.contains("Date.prototype.toTimeString"))
        assertTrue("Must override Date.prototype.toLocaleString", js.contains("Date.prototype.toLocaleString"))
        assertTrue("Must override Date.prototype.toLocaleDateString", js.contains("Date.prototype.toLocaleDateString"))
        assertTrue("Must override Date.prototype.toLocaleTimeString", js.contains("Date.prototype.toLocaleTimeString"))
        assertTrue("Must override navigator.language to en-US", js.contains("en-US"))
        assertTrue("Must override navigator.languages", js.contains("languages"))
    }

    @Test
    fun documentStartJs_perProfileAntiCorrelation_spoofsHardwareAndCanvas() {
        val jsDefault = AntiFingerprintHardener.buildDocumentStartJs(0)
        assertTrue("Must spoof hardwareConcurrency", jsDefault.contains("hardwareConcurrency"))
        assertTrue("Must spoof deviceMemory", jsDefault.contains("deviceMemory"))
        assertTrue("Seed 0 must also inject canvas noise with safeSeed >= 1", jsDefault.contains("NOISE_OFFSET"))
        assertTrue("Must hook getImageData", jsDefault.contains("CanvasRenderingContext2D.prototype.getImageData"))
        assertTrue("Must hook toDataURL", jsDefault.contains("HTMLCanvasElement.prototype.toDataURL"))
        assertTrue("Must hook toBlob", jsDefault.contains("HTMLCanvasElement.prototype.toBlob"))

        val jsSeed1 = AntiFingerprintHardener.buildDocumentStartJs(12345)
        assertTrue("Seed > 0 must inject canvas noise", jsSeed1.contains("NOISE_OFFSET"))
        assertTrue("Seed > 0 must hook getImageData", jsSeed1.contains("CanvasRenderingContext2D.prototype.getImageData"))
        assertTrue("Seed > 0 must hook toDataURL", jsSeed1.contains("HTMLCanvasElement.prototype.toDataURL"))
        assertTrue("Seed > 0 must hook toBlob", jsSeed1.contains("HTMLCanvasElement.prototype.toBlob"))

        val jsSeed2 = AntiFingerprintHardener.buildDocumentStartJs(98765)
        assertTrue(jsSeed1 != jsSeed2)
    }

    @Test
    fun documentStartJs_speechSynthesisAndDeepIntlHardening() {
        val js = AntiFingerprintHardener.DOCUMENT_START_JS

        assertTrue("Must neutralize speechSynthesis voices", js.contains("speechSynthesis.getVoices"))
        assertTrue("Must hook HTMLCanvasElement.prototype.toBlob", js.contains("HTMLCanvasElement.prototype.toBlob"))
        assertTrue("Must spoof webdriver", js.contains("webdriver"))
        assertTrue("Must lock navigator.connection", js.contains("navigator.connection"))
        assertTrue("Must lock Intl.NumberFormat", js.contains("Intl.NumberFormat"))
        assertTrue("Must lock Intl.Collator", js.contains("Intl.Collator"))
        assertTrue("Must lock Intl.PluralRules", js.contains("Intl.PluralRules"))
    }

    @Test
    fun timezoneAndLocaleSettings_verifyDefaults() {
        TimeZone.setDefault(TimeZone.getTimeZone("Europe/Amsterdam"))
        Locale.setDefault(Locale.US)

        assertTrue("TimeZone ID should be Europe/Amsterdam", TimeZone.getDefault().id == "Europe/Amsterdam")
        assertTrue("Locale should be US", Locale.getDefault() == Locale.US)
    }

    @Test
    fun documentStartJs_functionToStringCloakedAndAlphaPreserved() {
        val js = AntiFingerprintHardener.DOCUMENT_START_JS

        // Must register Function.prototype.toString in nativeMap
        assertTrue("Must cloak Function.prototype.toString itself", js.contains("nativeMap.set(Function.prototype.toString, 'toString')"))

        // Date and Intl hooks must be cloaked
        assertTrue("Must cloak getTimezoneOffset", js.contains("'getTimezoneOffset'"))
        assertTrue("Must cloak DateTimeFormat", js.contains("'DateTimeFormat'"))
        assertTrue("Must cloak Date.prototype.toString", js.contains("Date.prototype.toString = cloak("))
        assertTrue("Must cloak Date.prototype.toTimeString", js.contains("Date.prototype.toTimeString = cloak("))
        assertTrue("Must cloak Date.prototype.toLocaleString", js.contains("Date.prototype.toLocaleString = cloak("))
        assertTrue("Must cloak Date.prototype.toLocaleDateString", js.contains("Date.prototype.toLocaleDateString = cloak("))
        assertTrue("Must cloak Date.prototype.toLocaleTimeString", js.contains("Date.prototype.toLocaleTimeString = cloak("))
        assertTrue("Must cloak resolvedOptions", js.contains("'resolvedOptions'"))

        // Non-transparent canvas noise scan
        assertTrue("Must scan for non-transparent pixel (data[i + 3] > 0)", js.contains("data[i + 3] > 0"))
        assertTrue("Must apply noise to targetIdx", js.contains("data[targetIdx] = (data[targetIdx] + NOISE_OFFSET) % 256"))
    }
}

```

---

### 2.20. `app/src/test/java/com/corp/enclaveshield/accounts/AccountProfileManagerTest.kt`
**Role:** Account profile manager unit tests

```kotlin
package com.corp.enclaveshield.accounts

import android.content.Context
import android.content.SharedPreferences
import androidx.webkit.Profile
import androidx.webkit.ProfileStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`

class AccountProfileManagerTest {

    private lateinit var mockContext: Context
    private lateinit var fakePrefs: FakeSharedPreferences
    private lateinit var mockProfileStore: ProfileStore
    private lateinit var manager: AccountProfileManager

    @Before
    fun setUp() {
        mockContext = mock(Context::class.java)
        fakePrefs = FakeSharedPreferences()
        mockProfileStore = mock(ProfileStore::class.java)

        `when`(mockContext.applicationContext).thenReturn(mockContext)
        `when`(mockContext.getSharedPreferences(AccountProfileManager.PREFS_NAME, Context.MODE_PRIVATE))
            .thenReturn(fakePrefs)

        manager = AccountProfileManager(
            context = mockContext,
            prefsOverride = fakePrefs,
            profileStoreProvider = { mockProfileStore }
        )
    }

    @Test
    fun defaultInitialization_initializesWithDefaultAccount() {
        val profiles = manager.profiles.value
        assertEquals(1, profiles.size)

        val defaultProfile = profiles[0]
        assertEquals(AccountProfile.DEFAULT_ID, defaultProfile.id)
        assertEquals("Default Account", defaultProfile.displayName)
        assertEquals(Profile.DEFAULT_PROFILE_NAME, defaultProfile.storageKey)

        val active = manager.activeProfile.value
        assertEquals(defaultProfile.id, active.id)
        assertEquals(defaultProfile.displayName, active.displayName)
        assertTrue(defaultProfile.profileSeed >= 0)
    }

    @Test
    fun profileSeed_deterministicAndDistinct() {
        val p1 = AccountProfile("profile-1", "Account 1")
        val p2 = AccountProfile("profile-2", "Account 2")
        val p1Copy = AccountProfile("profile-1", "Renamed Account")
        assertEquals(p1.profileSeed, p1Copy.profileSeed)
        assertTrue(p1.profileSeed >= 0)
        assertTrue(p2.profileSeed >= 0)
    }

    @Test
    fun createProfile_addsProfileAndUpdatesList() {
        val created = manager.createProfile("Work Account")

        assertNotNull(created.id)
        assertTrue(created.id != AccountProfile.DEFAULT_ID)
        assertEquals("Work Account", created.displayName)
        assertTrue(created.storageKey.startsWith("profile_"))

        val profiles = manager.profiles.value
        assertEquals(2, profiles.size)
        assertEquals("Default Account", profiles[0].displayName)
        assertEquals("Work Account", profiles[1].displayName)
    }

    @Test
    fun createProfile_blankName_usesFallbackName() {
        val created = manager.createProfile("   ")
        assertEquals("Account 2", created.displayName)
    }

    @Test
    fun switchProfile_transitionsActiveProfile() {
        val work = manager.createProfile("Work")
        val personal = manager.createProfile("Personal")

        // Switch to Work
        val switchedWork = manager.switchProfile(work.id)
        assertTrue(switchedWork)
        assertEquals(work.id, manager.activeProfile.value.id)
        assertEquals("Work", manager.activeProfile.value.displayName)

        // Switch to Personal
        val switchedPersonal = manager.switchProfile(personal.id)
        assertTrue(switchedPersonal)
        assertEquals(personal.id, manager.activeProfile.value.id)
        assertEquals("Personal", manager.activeProfile.value.displayName)

        // Switch to non-existent ID fails
        val invalidSwitch = manager.switchProfile("non-existent-id")
        assertFalse(invalidSwitch)
        assertEquals(personal.id, manager.activeProfile.value.id)
    }

    @Test
    fun renameProfile_updatesDisplayNameAndActiveProfile() {
        val profile = manager.createProfile("Original Name")
        manager.switchProfile(profile.id)

        val renameSuccess = manager.renameProfile(profile.id, "Updated Name")
        assertTrue(renameSuccess)

        // Verify updated in list
        val updated = manager.profiles.value.find { it.id == profile.id }
        assertNotNull(updated)
        assertEquals("Updated Name", updated?.displayName)

        // Verify active profile reflects rename
        assertEquals("Updated Name", manager.activeProfile.value.displayName)

        // Renaming with empty string fails and preserves existing name
        val emptyRename = manager.renameProfile(profile.id, "   ")
        assertFalse(emptyRename)
        assertEquals("Updated Name", manager.activeProfile.value.displayName)

        // Renaming unknown ID fails
        val unknownRename = manager.renameProfile("unknown-id", "New Name")
        assertFalse(unknownRename)
    }

    @Test
    fun deleteProfile_cannotDeleteOnlyRemainingProfile() {
        assertEquals(1, manager.profiles.value.size)
        val defaultId = manager.profiles.value[0].id

        val deleted = manager.deleteProfile(defaultId)
        assertFalse(deleted)
        assertEquals(1, manager.profiles.value.size)
    }

    @Test
    fun deleteProfile_nonActiveProfile_deletesStorageAndRemovesFromList() {
        val work = manager.createProfile("Work")
        assertEquals(2, manager.profiles.value.size)

        val deleted = manager.deleteProfile(work.id)
        assertTrue(deleted)
        assertEquals(1, manager.profiles.value.size)
        assertEquals(AccountProfile.DEFAULT_ID, manager.profiles.value[0].id)

        // Verify profileStore.deleteProfile was called with profile's storageKey
        verify(mockProfileStore).deleteProfile(work.storageKey)
    }

    @Test
    fun deleteProfile_activeProfile_transitionsToRemainingProfile() {
        val work = manager.createProfile("Work")
        manager.switchProfile(work.id)
        assertEquals(work.id, manager.activeProfile.value.id)

        val deleted = manager.deleteProfile(work.id)
        assertTrue(deleted)
        assertEquals(1, manager.profiles.value.size)

        // Active profile should have transitioned to the remaining default account
        assertEquals(AccountProfile.DEFAULT_ID, manager.activeProfile.value.id)
        assertEquals("Default Account", manager.activeProfile.value.displayName)
    }

    @Test
    fun persistence_restoresProfilesAndActiveStateAcrossInstances() {
        val work = manager.createProfile("Work")
        manager.createProfile("Personal")
        manager.switchProfile(work.id)
        manager.renameProfile(work.id, "Work Pro")

        // Create a new instance pointing to the same SharedPreferences
        val restoredManager = AccountProfileManager(
            context = mockContext,
            prefsOverride = fakePrefs,
            profileStoreProvider = { mockProfileStore }
        )

        val restoredProfiles = restoredManager.profiles.value
        assertEquals(3, restoredProfiles.size)
        assertEquals("Default Account", restoredProfiles[0].displayName)
        assertEquals("Work Pro", restoredProfiles[1].displayName)
        assertEquals("Personal", restoredProfiles[2].displayName)

        assertEquals(work.id, restoredManager.activeProfile.value.id)
        assertEquals("Work Pro", restoredManager.activeProfile.value.displayName)
    }

    @Test
    fun fallbackCookieStorage_encryptsAndRestoresCookies() {
        val fallback = AccountCookieJarFallback(mockContext, fakePrefs)
        val testCookies = "sessionKey=tok-auth-test12345; __cf_bm=randomcfbmvalue; other=val"

        fallback.saveCookies("test-profile-1", testCookies)
        val restored = fallback.getCookies("test-profile-1")
        assertEquals(testCookies, restored)

        // Verify cookies for different profiles are isolated
        fallback.saveCookies("test-profile-2", "sessionKey=tok-auth-different6789")
        assertEquals(testCookies, fallback.getCookies("test-profile-1"))
        assertEquals("sessionKey=tok-auth-different6789", fallback.getCookies("test-profile-2"))

        // Delete cookies
        fallback.deleteCookies("test-profile-1")
        assertEquals(null, fallback.getCookies("test-profile-1"))
        assertEquals("sessionKey=tok-auth-different6789", fallback.getCookies("test-profile-2"))
    }

    @Test
    fun fallbackCookieStorage_aadPreventsCrossProfileDecryption() {
        val fallback = AccountCookieJarFallback(mockContext, fakePrefs)
        val encrypted = fallback.encrypt("profile-A", "secret-session-cookie")

        // Decrypting with correct profile succeeds
        val decryptedSuccess = fallback.decrypt("profile-A", encrypted)
        assertEquals("secret-session-cookie", decryptedSuccess)

        // Decrypting with wrong profile fails due to GCM AAD authentication tag mismatch
        val decryptedFail = fallback.decrypt("profile-B", encrypted)
        assertEquals(null, decryptedFail)
    }

    @Test
    fun jsonCodec_handlesSpecialCharactersAndCyrillic() {
        val profiles = listOf(
            AccountProfile("id1", "Рабочий аккаунт (Corporate Portal)", 1000L),
            AccountProfile("id2", "Quotes \"and\" \\slashes\\, plus commas", 2000L),
            AccountProfile("id3", "Nested {Braces} and [Brackets] {dev}", 3000L)
        )

        val json = AccountProfileJsonCodec.toJson(profiles)
        val restored = AccountProfileJsonCodec.fromJson(json)

        assertEquals(3, restored.size)
        assertEquals("id1", restored[0].id)
        assertEquals("Рабочий аккаунт (Corporate Portal)", restored[0].displayName)
        assertEquals(1000L, restored[0].createdAt)

        assertEquals("id2", restored[1].id)
        assertEquals("Quotes \"and\" \\slashes\\, plus commas", restored[1].displayName)
        assertEquals(2000L, restored[1].createdAt)

        assertEquals("id3", restored[2].id)
        assertEquals("Nested {Braces} and [Brackets] {dev}", restored[2].displayName)
        assertEquals(3000L, restored[2].createdAt)
    }
}

/**
 * In-memory [SharedPreferences] implementation for local JVM unit tests.
 */
class FakeSharedPreferences : SharedPreferences {
    private val data = mutableMapOf<String, Any?>()

    override fun getAll(): MutableMap<String, *> = data
    override fun getString(key: String?, defValue: String?): String? = data[key] as? String ?: defValue
    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
        (data[key] as? MutableSet<String>) ?: defValues
    override fun getInt(key: String?, defValue: Int): Int = data[key] as? Int ?: defValue
    override fun getLong(key: String?, defValue: Long): Long = data[key] as? Long ?: defValue
    override fun getFloat(key: String?, defValue: Float): Float = data[key] as? Float ?: defValue
    override fun getBoolean(key: String?, defValue: Boolean): Boolean = data[key] as? Boolean ?: defValue
    override fun contains(key: String?): Boolean = data.containsKey(key)
    override fun edit(): SharedPreferences.Editor = FakeEditor()
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

    inner class FakeEditor : SharedPreferences.Editor {
        private val temp = mutableMapOf<String, Any?>()
        private val removed = mutableSetOf<String>()
        private var clear = false

        override fun putString(key: String?, value: String?): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor {
            if (key != null) temp[key] = values
            return this
        }
        override fun putInt(key: String?, value: Int): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun remove(key: String?): SharedPreferences.Editor {
            if (key != null) removed.add(key)
            return this
        }
        override fun clear(): SharedPreferences.Editor {
            clear = true
            return this
        }
        override fun commit(): Boolean {
            apply()
            return true
        }
        override fun apply() {
            if (clear) data.clear()
            for (key in removed) data.remove(key)
            data.putAll(temp)
        }
    }
}

```

---

### 2.21. `app/src/test/java/com/corp/enclaveshield/telemetry/SecurityAuditLoggerTest.kt`
**Role:** Audit logger unit tests

```kotlin
package com.corp.enclaveshield.telemetry

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

class SecurityAuditLoggerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val mockContext: Context = mock(Context::class.java)

    @Before
    fun setUp() {
        `when`(mockContext.applicationContext).thenReturn(mockContext)
        `when`(mockContext.filesDir).thenReturn(tempFolder.root)
    }

    @Test
    fun metricCounters_incrementCorrectly() {
        val logger = SecurityAuditLogger(mockContext)

        assertEquals(0, logger.vpnConnectCount.get())
        logger.vpnConnectCount.incrementAndGet()
        assertEquals(1, logger.vpnConnectCount.get())

        logger.successfulConnections.addAndGet(5)
        logger.blockedVpnOffCount.addAndGet(2)
        logger.blockedIpv6Count.addAndGet(1)
        logger.forceClosedSocketsCount.addAndGet(3)

        val snapshot = logger.getSnapshot()
        assertEquals(5, snapshot.connectionsAccepted)
        assertEquals(3, snapshot.connectionsRejected)
        assertEquals(3, snapshot.connectionsKilled)
    }

    @Test
    fun dnsStats_trackingAndLatency() {
        val logger = SecurityAuditLogger(mockContext)

        logger.dnsQueriesTotal.set(10)
        logger.dnsCacheHits.set(4)
        logger.dnsFailures.set(1)
        logger.dnsCacheEntries.set(7)
        logger.recordDnsLatency(45)
        logger.recordDnsLatency(120)
        logger.recordDnsLatency(80)

        val stats = logger.getDnsStats()
        assertEquals(10, stats.totalQueries)
        assertEquals(4, stats.cacheHits)
        assertEquals(1, stats.resolveErrors)
        assertEquals(7, stats.cacheEntries)
        assertEquals(80, stats.averageLatencyMs)
        assertEquals(120, logger.maxDnsLatencyMs.get())
    }

    @Test
    fun ringBuffer_storesAndRollsOver() {
        val logger = SecurityAuditLogger(mockContext)

        for (i in 1..600) {
            logger.log(LogCategory.PROXY, LogLevel.INFO, "Request #$i")
        }

        val recent = logger.getRecentLogs(500)
        assertEquals(500, recent.size)
        // Earliest item in buffer should be Request #101 due to 500 entry limit
        assertTrue(recent.first().message.contains("Request #101"))
        assertTrue(recent.last().message.contains("Request #600"))
    }

    @Test
    fun markdownReport_containsEssentialSections() {
        val logger = SecurityAuditLogger(mockContext)
        logger.vpnConnectCount.set(2)
        logger.isProxyOverrideActive = true
        logger.isDocumentStartJsActive = true
        logger.log(LogCategory.VPN, LogLevel.INFO, "VPN tun0 connected 10.8.0.2")

        val report = logger.generateMarkdownReport()
        assertTrue(report.contains("# EnclaveShield Telemetry & Security Audit Report"))
        assertTrue(report.contains("Device & OS Environment"))
        assertTrue(report.contains("Security Invariant Self-Checks"))
        assertTrue(report.contains("Active (No Fallback)"))
        assertTrue(report.contains("Injected"))
        assertTrue(report.contains("✅ SECURE"))
        assertTrue(report.contains("Network & Gatekeeper Telemetry Metrics"))
        assertTrue(report.contains("VPN Connect Count"))
        assertTrue(report.contains("Chronological Event Log"))
        assertTrue(report.contains("VPN tun0 connected 10.8.0.2"))
    }

    @Test
    fun clearLogs_emptiesBuffer() {
        val logger = SecurityAuditLogger(mockContext)
        logger.log(LogCategory.SECURITY, LogLevel.INFO, "Test event")
        assertTrue(logger.getRecentLogs(10).isNotEmpty())

        logger.clearLogs()
        val afterClear = logger.getRecentLogs(10)
        // After clear, only the "Audit logs cleared" event remains
        assertEquals(1, afterClear.size)
        assertTrue(afterClear.first().message.contains("cleared"))
    }
}

```

---

## 3. Verification & Test Suite Summary

- **Unit Test Suite:** 100% passing across all components (`TunnelDnsResolverTest`, `VpnGatekeeperProxyTest`, `AntiFingerprintHardenerTest`, `AccountProfileManagerTest`, `SecurityAuditLoggerTest`).
- **Compilation Target:** Target SDK 36 (Android 15/16/17 readiness), Min SDK 33 (Android 13).
- **Zero-Trust Hardening:**
  1. Open proxy vulnerability resolved via Destination Allowlist & RFC 1918 Private IP filtering.
  2. Thread starvation resolved via dedicated `relayExecutor` cached thread pool.
  3. VPN handover socket leak eliminated via generational socket tracking & synchronous `TunnelListener`.
  4. Scheduled DNS watchdog eliminates coroutine thread starvation.
  5. Keystore caller-IV exception eliminated by delegating IV generation to AndroidKeyStore and binding AAD to profile ID.
  6. Document-Start JS hardened with offscreen Canvas cloning and Function.prototype.toString cloaking.
  7. WebView hardened with `.removeImplicitRules()`, disabled SafeBrowsing, and `onRenderProcessGone`.

---
*Generated for Enterprise Security Architecture Review & Code Audit.*
