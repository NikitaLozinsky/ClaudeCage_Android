package com.example.claudecageand.ui

/**
 * Self-contained bilingual string catalog for ClaudeCageAnd UI.
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

    fun btnReturnToClaude(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "← Claude"
        UiLanguage.EN -> "← Claude"
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
        UiLanguage.RU -> "Принцип Fail-Closed: приложение разрывает все соединения в ту же миллисекунду, когда отключается Amnezia VPN. Для сайта Claude это выглядит как обычная потеря сигнала Wi-Fi/LTE. Ваш реальный IP-адрес никогда не попадёт в сеть."
        UiLanguage.EN -> "Fail-Closed principle: the app terminates all connections in the very millisecond Amnezia VPN drops. To Claude's servers, this appears as normal Wi-Fi/LTE signal loss. Your real IP address can never leak to the network."
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
        UiLanguage.RU -> "Новый аккаунт Claude"
        UiLanguage.EN -> "New Claude Account"
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

    fun btnReload(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "🔄 Обновить"
        UiLanguage.EN -> "🔄 Reload"
    }

    fun toastReloading(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Перезагрузка страницы..."
        UiLanguage.EN -> "Reloading page..."
    }

    fun btnPurgeSession(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "🧹 Очистить кэш и сессию"
        UiLanguage.EN -> "🧹 Purge Cache & Session"
    }

    fun confirmPurgeSessionTitle(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Сброс кэша и куки"
        UiLanguage.EN -> "Purge Cache & Cookies"
    }

    fun confirmPurgeSessionMsg(lang: UiLanguage, profileName: String): String = when (lang) {
        UiLanguage.RU -> "Очистить куки, локальное хранилище и кэш для профиля «$profileName»? Это устранит любые залипания Cloudflare, но вам потребуется снова войти в аккаунт."
        UiLanguage.EN -> "Clear cookies, local storage, and cache for profile \"$profileName\"? This clears any Cloudflare loops, but you will need to sign in again."
    }

    fun toastSessionPurged(lang: UiLanguage): String = when (lang) {
        UiLanguage.RU -> "Кэш и сессия профиля очищены!"
        UiLanguage.EN -> "Profile cache and session purged!"
    }
}
