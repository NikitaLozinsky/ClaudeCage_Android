package com.example.claudecageand

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
import com.example.claudecageand.accounts.AccountProfile
import com.example.claudecageand.net.VpnTunnelState
import com.example.claudecageand.security.AntiFingerprintHardener
import com.example.claudecageand.ui.AppIconOption
import com.example.claudecageand.ui.UiLanguage
import com.example.claudecageand.ui.UiStrings
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
 *    are hosted in [ClaudeCageApp] so that Activity recreation does NOT recreate or clear proxy state.
 * 2. In [onDestroy], [ProxyController.clearProxyOverride] is NEVER called. The proxy override
 *    remains locked for the lifetime of the Linux process to prevent fail-open windows.
 * 3. User-Agent is sanitized: WebView markers ("; wv", "Version/4.0 ") are stripped.
 * 4. Non-HTTPS schemes in [WebViewClient.shouldOverrideUrlLoading] are blocked.
 * 5. Document-start JS hardening disables WebRTC, spoofs timezone to Europe/Amsterdam and locale to en-US.
 * 6. File and image uploads in Claude chat are supported via [WebChromeClient.onShowFileChooser].
 * 7. Bilingual UI (RU/EN) is maintained entirely in Kotlin memory without modifying JVM Locale.
 */
class MainActivity : AppCompatActivity() {

    private val app: ClaudeCageApp
        get() = ClaudeCageApp.instance

    private lateinit var vpnStatusBar: View
    private lateinit var tvVpnStatus: TextView
    private lateinit var tvVpnSubStatus: TextView
    private lateinit var btnDiagnostics: TextView
    private lateinit var btnReturnToClaude: TextView
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
            if (!url.startsWith("https://claude.ai/") && url != "https://claude.ai") {
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
        ClaudeCageApp.enforceUsLocaleAndTimezone(base)
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
        ClaudeCageApp.enforceUsLocaleAndTimezone(this)
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
        btnReturnToClaude = findViewById(R.id.btnReturnToClaude)
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
        btnReturnToClaude.setOnClickListener {
            it.performHapticFeedback(HapticFeedbackConstants.CONFIRM)
            btnReturnToClaude.visibility = View.GONE
            webView?.loadUrl(CLAUDE_URL, mapOf("Accept-Language" to "en-US,en;q=0.9"))
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
        btnReturnToClaude.text = UiStrings.btnReturnToClaude(lang)
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
        ClaudeCageApp.enforceUsLocaleAndTimezone(this)
        val current = app.vpnStateMonitor.getCurrentTunnelState()
        val proxyPort = app.vpnGatekeeperProxy.listeningPort
        refreshStatusBarText(current, proxyPort, app.uiLanguageManager.language.value)
    }

    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        ClaudeCageApp.enforceUsLocaleAndTimezone(this)
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
        ClaudeCageApp.enforceUsLocaleAndTimezone(this)

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

        // Configure WebSettings for claude.ai compatibility & privacy
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
                    btnReturnToClaude.visibility = View.VISIBLE
                } else if (url?.contains("claude.ai") == true) {
                    btnReturnToClaude.visibility = View.GONE
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
                        pendingDownloadFilename = filename.ifBlank { "claude_artifact.txt" }
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
            "ClaudeCageDownload"
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
                            window.ClaudeCageDownload.onBlobDownloaded(base64, '$safeName', '$safeMime');
                        };
                        reader.readAsDataURL(blob);
                    } catch (e) {
                        window.ClaudeCageDownload.onDownloadFailed(e.toString());
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
            wv.loadUrl(CLAUDE_URL, mapOf("Accept-Language" to "en-US,en;q=0.9"))
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

        // 5. Instantiate fresh WebView bound to targetProfile and load CLAUDE_URL
        hasLoadedInitialUrl = false
        initWebView(targetProfile)

        // 6. Reset return button
        btnReturnToClaude.visibility = View.GONE

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
                        "window.__claudeCageOffline = false; window.dispatchEvent(new Event('online'));",
                        null
                    )

                    if (!hasLoadedInitialUrl) {
                        waitingOverlay.visibility = View.GONE
                        wv.loadUrl(CLAUDE_URL, mapOf("Accept-Language" to "en-US,en;q=0.9"))
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
                        "window.__claudeCageOffline = true; window.dispatchEvent(new Event('offline'));",
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
                "Версии ClaudeCage, системного Chromium WebView, платформы Android и уровень харденинга."
            } else {
                "Active versions of ClaudeCage, Chromium WebView engine, Android OS platform, and hardening stage."
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
            "Изоляция сессий Claude: каждый аккаунт изолирован в отдельный контейнер с независимыми cookie, WebStorage и кэшем."
        } else {
            "Claude session isolation: each profile is containerized with isolated cookies, WebStorage, and cache."
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
            btnReturnToClaude.visibility = View.VISIBLE
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
        val clip = ClipData.newPlainText("ClaudeCage Audit Report", report)
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
            putExtra(Intent.EXTRA_SUBJECT, "ClaudeCage Security Audit Report")
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
            return "ClaudeCage v$appVersionName (Build $appVersionCode) • $stageHardening\n" +
                    "WebView: $webViewPackage $webViewVersion\n" +
                    "Android: Android $androidRelease (API $apiLevel) • Patch: $securityPatch\n" +
                    "Device: $deviceManufacturer $deviceModel ($architecture)"
        }

        fun toDetailedReport(): String {
            return """
                --- ClaudeCage Component Versions ---
                App: ClaudeCage v$appVersionName (Build $appVersionCode)
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
                val clip = ClipData.newPlainText("ClaudeCage Versions", versions.toDetailedReport())
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
        private const val CLAUDE_URL = "https://claude.ai"
        private const val DIAGNOSTIC_URL = "https://browserleaks.com/ip"
        private const val PREFS_UI_COLLAPSE = "claudecage_ui_collapse_prefs"
        private const val KEY_TOPBAR_COLLAPSED = "is_top_bar_collapsed"
        private const val KEY_ANCHOR_X = "anchor_x"
        private const val KEY_ANCHOR_Y = "anchor_y"
        private const val PREFS_SECURITY_SETTINGS = "claudecage_security_prefs"
        private const val KEY_FLAG_SECURE = "is_flag_secure_enabled"
    }
}
