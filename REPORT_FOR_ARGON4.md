# Отчёт об Архитектурных Доработках и Улучшениях Безопасности
## Проект: ClaudeCage v1.4 (Build 5) • Hardening Stage 11
**Для ревьюера:** Gemini Argon 4 (Frontier Security & Architecture Model)  
**Дата:** 28 октября 2026 г.  
**Целевая платформа:** Android 13+ (Target SDK 36), Samsung Galaxy S25 Ultra (Android 17, One UI 9)  
**Целевой сервис:** Anthropic Claude (`https://claude.ai`)  

---

### 1. Краткое резюме (Executive Summary)

В данном обновлении мы **не переписывали архитектуру с нуля** — базовые компоненты (Zero-Leak SOCKS5 прокси, Fail-Closed TCP DNS с True SWR и Watchdog, Document-Start JS для WebRTC, Multi-Account ProfileStore) функционируют надёжно.

Основная цель релиза **v1.4 (Build 5, Stage 11)** — устранение тонких векторов деанонимизации на уровне ядра ОС и антифрод-скриптов Cloudflare/Turnstile, а также кардинальное повышение эргономики интерфейса (плавающий якорь и панель управления).

Ниже подробно описаны 4 ключевые проблемы, принятые архитектурные решения и конкретные фрагменты внедрённого кода.

---

### 2. Проблема 1: Риск утечки трафика в открытую сеть при падении туннеля на уровне ядра Linux

#### В чём заключалась проблема
Ранее при получении системного события `onLost` от `ConnectivityManager` в `VpnStateMonitor.kt` вызывался метод:
```kotlin
connectivityManager.bindProcessToNetwork(null)
```
**Уязвимость:** сброс привязки процесса к `null` мгновенно возвращал приложение на сетевой маршрут по умолчанию (Default Network — сотовая связь 5G/LTE или физический Wi-Fi). Если Chromium WebView или фоновый пул соединений в этот момент инициировал исходящий сокет до того, как прикладной Kill-Switch разорвёт соединения, пакет успевал уйти в открытую сеть, раскрывая реальный IP-адрес провайдера и геолокацию.

#### Как решена (Kernel Dead-Network Pinning)
Мы запретили вызов `bindProcessToNetwork(null)` при падении или отключении VPN. Процесс намеренно остаётся привязанным к дескриптору уже закрытой сети туннеля (`dead network handle`). 

В результате само ядро Linux на уровне системных вызовов сокетов (`libc::connect`, `sendto`) немедленно отсекает любые попытки выхода пакетов наружу с ошибкой `ENETUNREACH` (Network unreachable), исключая утечку данных даже при любых сбоях или гонках внутри Android Framework.

#### Пример из кода (`VpnStateMonitor.kt`)
```kotlin
// net/VpnStateMonitor.kt

@Synchronized
private fun onVpnDisconnected() {
    val previousState = currentTunnelState
    if (previousState is VpnTunnelState.Connected) {
        currentGeneration.incrementAndGet()
        currentTunnelState = VpnTunnelState.Disconnected
        
        // Stage 11: KERNEL DEAD-NETWORK PINNING
        // ВНИМАНИЕ: connectivityManager.bindProcessToNetwork(null) НЕ вызывается!
        // Процесс остаётся привязан к недействительному дескриптору сети туннеля (dead network handle).
        // Ядро Linux пресекает 100% не-loopback пакетов с ошибкой ENETUNREACH,
        // гарантируя Fail-Closed изоляцию даже при сбоях в ОС Android.
        
        notifyListeners(VpnTunnelState.Disconnected)
    }
}
```

---

### 3. Проблема 2: Детекция антифрод-системами Cloudflare Turnstile и фингерпринтинг устройства

#### В чём заключалась проблема
1. **Отсутствие Client Hints (`navigator.userAgentData`):** Современный Cloudflare Turnstile проверяет соответствие между User-Agent строкой и объектом `navigator.userAgentData`. В стандартном Android WebView данный API часто отсутствует или возвращает значения, не совпадающие с десктопными/мобильными заголовками Chromium.
2. **Аудио-отпечатки (`AudioContext`):** Скрипты антифрода генерируют звуковой сигнал через Web Audio API и снимают отпечаток частотной характеристики через `AudioBuffer.prototype.getChannelData`.
3. **WebGL readPixels Fingerprinting:** Тесты BrowserLeaks и антифрод запрашивают рендеринг тестовой сцены через WebGL и считывают массив байтов кадра через `readPixels()`.

#### Как решена
В `AntiFingerprintHardener.kt` внедрены три рубежа маскировки, выполняемые в `DOCUMENT_START_JS` до загрузки первого скрипта сайта:
1. **W3C Polyfill `navigator.userAgentData`:** метод `getHighEntropyValues()` отдаёт консистентные бренды `Chromium` и `Google Chrome`, платформу `Android` и точную модель устройства пользователя (`SM-S938B`) с маскировкой под актуальную мажорную версию Chromium.
2. **AudioBuffer Micro-Noise:** перехвачен `AudioBuffer.prototype.getChannelData` с подмешиванием детерминированного микрошума `1e-7 * NOISE_OFFSET`, ломающего хэш отпечатка без слышимых искажений.
3. **WebGL readPixels Micro-Noise:** перехвачен `readPixels` в `WebGLRenderingContext` и `WebGL2RenderingContext` с зашумлением первого непрозрачного пикселя (`pixels[i] = (pixels[i] + NOISE_OFFSET) % 256`).

#### Пример из кода (`AntiFingerprintHardener.kt`)
```javascript
// security/AntiFingerprintHardener.kt

// 7.1 AudioBuffer Micro-Noise Spoofer
try {
    if (window.AudioBuffer && AudioBuffer.prototype.getChannelData) {
        const origGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = cloak(function(channel) {
            const buffer = origGetChannelData.call(this, channel);
            if (buffer && buffer.length > 0) {
                buffer[0] = buffer[0] + (1e-7 * NOISE_OFFSET);
            }
            return buffer;
        }, 'getChannelData');
    }

    // 7.2 WebGL readPixels Micro-Noise
    const hookWebGLReadPixels = (proto) => {
        if (!proto || !proto.readPixels) return;
        const origReadPixels = proto.readPixels;
        proto.readPixels = cloak(function(x, y, width, height, format, type, pixels) {
            origReadPixels.call(this, x, y, width, height, format, type, pixels);
            if (pixels && pixels.length > 0) {
                for (let i = 0; i < pixels.length; i += 4) {
                    if (pixels[i + 3] > 0 || pixels.length < 4) {
                        pixels[i] = (pixels[i] + NOISE_OFFSET) % 256;
                        break;
                    }
                }
            }
        }, 'readPixels');
    };
    if (window.WebGLRenderingContext) hookWebGLReadPixels(WebGLRenderingContext.prototype);
    if (window.WebGL2RenderingContext) hookWebGLReadPixels(WebGL2RenderingContext.prototype);
} catch (e) {}

// 10.5 navigator.userAgentData Client Hints Polyfill
try {
    const ua = navigator.userAgent || '';
    const chromeMatch = ua.match(/Chrome\/([0-9]+)/);
    const chromeMajor = chromeMatch ? chromeMatch[1] : '133';

    const brands = [
        { brand: 'Not(A:Brand', version: '99' },
        { brand: 'Google Chrome', version: chromeMajor },
        { brand: 'Chromium', version: chromeMajor }
    ];

    const uad = {
        brands: brands,
        mobile: true,
        platform: 'Android',
        getHighEntropyValues: cloak(function(hints) {
            return Promise.resolve({
                brands: brands,
                mobile: true,
                platform: 'Android',
                platformVersion: '15.0.0',
                architecture: 'arm',
                model: 'SM-S938B',
                bitness: '64'
            });
        }, 'getHighEntropyValues')
    };
    Object.defineProperty(navigator, 'userAgentData', {
        get: cloak(function() { return uad; }, 'get userAgentData'),
        configurable: true
    });
} catch (e) {}
```

---

### 4. Проблема 3: Жестовое управление плавающим якорем безопасности и баги геометрии

#### В чём заключалась проблема
1. **Принудительное прилипание к краям (Snap-to-Edge):** якорь принудительно анимировался строго к левой или правой границе экрана. Пользователь не мог расположить его свободно в удобном месте экрана (например, в центре или возле клавиатуры).
2. **Скачок координат в (0,0):** при динамическом переключении формы (`PILL` $\to$ `SQUARE` $\to$ `CIRCLE`) из-за пересчёта `LayoutParams` якорь на доли секунды скакал в левый верхний угол экрана.
3. **Конфликт тапов:** одиночный клик (разворачивание верхней панели) конфликтовал с двойным кликом (смена формы), а назойливые системные Toast-уведомления перекрывали контент страницы.

#### Как решена
1. **Свободное перемещение по всему экрану (`clampAndSaveAnchorPosition`):** упразднён принудительный снаппинг к краям. Якорь свободно следует за пальцем в любую точку экрана и сохраняет координаты в `SharedPreferences`, оставаясь в пределах безопасных отступов (`4dp`).
2. **Устранение скачка координат:** перед сменой габаритов формы кэшируются координаты `prevX`/`prevY`, а изменение размеров оборачивается в `TransitionManager.beginDelayedTransition`.
3. **Динамическая статусная граница (Dynamic Border):** тонкая рамка якоря окрашивается в реальном времени под тёмный фон `#EB0D1117`:
   - 🟢 Зелёный (`#554ADE80`) — туннель защищён, трафик зашифрован.
   - 🟡 Янтарный (`#88FBBF24`) — задержка туннеля / Doze Mode.
   - 🔴 Красный (`#99F87171`) — туннель разорван, трафик наглухо блокирован ядром.
4. **Горизонтальный жест (Fling / Swipe):** быстрое горизонтальное смахивание циклически переключает форму якоря.
5. **Оптимизация задержек и тактильный отклик:** дебаунсинг одиночного тапа сокращён до **170 мс**, смена формы сопровождается мягким `CLOCK_TICK` вибрации без тостов, а в режиме `SQUARE` клик по монограмме аккаунта мгновенно открывает профили.

#### Пример из кода (`MainActivity.kt`)
```kotlin
// MainActivity.kt

// Свободное позиционирование без принудительного прилипания к краям
private fun clampAndSaveAnchorPosition(view: View) {
    val parent = view.parent as? View
    val parentWidth = parent?.width?.takeIf { it > 0 } ?: resources.displayMetrics.widthPixels
    val parentHeight = parent?.height?.takeIf { it > 0 } ?: resources.displayMetrics.heightPixels
    val marginPx = 4 * resources.displayMetrics.density
    val maxX = (parentWidth - view.width - marginPx).coerceAtLeast(marginPx)
    val maxY = (parentHeight - view.height - marginPx).coerceAtLeast(marginPx)

    val targetX = view.x.coerceIn(marginPx, maxX)
    val targetY = view.y.coerceIn(marginPx, maxY)

    view.x = targetX
    view.y = targetY

    val prefs = getSharedPreferences(PREFS_UI_COLLAPSE, Context.MODE_PRIVATE)
    prefs.edit()
        .putFloat(KEY_ANCHOR_X, targetX)
        .putFloat(KEY_ANCHOR_Y, targetY)
        .apply()
}

// Плавная смена формы с сохранением координат
private fun applyAnchorShape(shape: FloatingAnchorShape, animate: Boolean = true) {
    currentAnchorShape = shape
    val density = resources.displayMetrics.density

    val prevX = floatingSecurityAnchor.x
    val prevY = floatingSecurityAnchor.y

    if (animate) {
        (floatingSecurityAnchor.parent as? ViewGroup)?.let {
            TransitionManager.beginDelayedTransition(it)
        }
    }
    // ... настройка габаритов PILL (WRAP_CONTENT), SQUARE (38dp), CIRCLE (34dp) ...
    
    floatingSecurityAnchor.x = prevX
    floatingSecurityAnchor.y = prevY
    updateFloatingAnchorAppearance()

    floatingSecurityAnchor.post {
        clampAndSaveAnchorPosition(floatingSecurityAnchor)
    }
}
```

---

### 5. Проблема 4: Перегруженность панели статуса и неудобство меню диагностики

#### В чём заключалась проблема
1. В верхней панели находилось слишком много кнопок (диагностика, смена языка, аккаунты, перезагрузка, размер, свернуть), что создавало визуальный шум на мобильном экране.
2. В диалоге диагностики (`showDiagnosticsDialog()`) 11 кнопок управления располагались в самом низу длинного списка под всеми информационными блоками, вынуждая пользователя постоянно скроллить вниз для выполнения простых действий (перезагрузка, очистка логов, смена аккаунта).

#### Как решена
1. **Стилизация кнопок-пилюль:** кнопки верхней панели стилизованы ресурсом `@drawable/bg_topbar_btn_pill` с радиусом скругления 8dp и тонкой рамкой `#30363D`. Избыточные кнопки (`btnDiagnostics`, `btnLangToggle`) скрыты из верхней панели (клик по тексту статуса открывает диагностику).
2. **2-Колоночная сетка быстрых действий (Action Grid 6x2):** все действия перемещены в самый **верх** диалога диагностики над информационными карточками в виде компактной сетки из 12 кнопок:
   - `[ 🔄 Обновить ]` & `[ 👤 Аккаунты ]`
   - `[ 📋 Копировать ]` & `[ 📤 Поделиться ]`
   - `[ 🧪 BrowserLeaks ]` & `[ 🧹 Сброс логов ]`
   - `[ ⤡ Панель мини ]` & `[ 🎛️ Форма якоря ]`
   - `[ 🛡️ Recents: ВКЛ/ВЫКЛ ]` & `[ 🎨 Иконка ]`
   - `[ 📦 Версии ]` & `[ 🌐 Язык: RU/EN ]`

#### Пример из кода (`MainActivity.kt`)
```kotlin
// MainActivity.kt - showDiagnosticsDialog()

val gridCard = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    layoutParams = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
    ).apply {
        setMargins(0, 0, 0, (8 * density).toInt())
    }
    background = createCardBackground("#161B22", "#30363D", 12f)
    setPadding((6 * density).toInt(), (6 * density).toInt(), (6 * density).toInt(), (6 * density).toInt())
}

fun createGridButton(label: String, onClick: () -> Unit): MaterialButton {
    return MaterialButton(this).apply {
        text = label
        textSize = 11f
        isAllCaps = false
        val padV = (8 * density).toInt()
        val padH = (6 * density).toInt()
        setPadding(padH, padV, padH, padV)
        minHeight = 0
        minimumHeight = (36 * density).toInt()
        layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
            val m = (3 * density).toInt()
            setMargins(m, m, m, m)
        }
        setOnClickListener { onClick() }
    }
}

addGridRow(btnReload, btnAccounts)
addGridRow(btnCopy, btnShare)
addGridRow(btnLeaks, btnClear)
addGridRow(btnToggleBarSize, btnShape)
addGridRow(btnToggleSecure, btnIcon)
addGridRow(btnVersions, btnLang)

contentLayout.addView(gridCard) // Размещено на самом верху диалога над карточками!
```

---

### 6. Статус верификации и итоговый бинарник

1. **Модульные тесты (`./gradlew testDebugUnitTest`):**
   - **Результат:** `BUILD SUCCESSFUL`
   - **Статистика:** **64 из 64 тестов пройдены успешно (0 сбоев)**.
   - Добавлены тесты `documentStartJs_audioAndWebGlNoiseInjected` и `documentStartJs_clientHintsUserAgentDataSpoofed` в [`AntiFingerprintHardenerTest.kt`](file:///home/milk13/IdeaProjects/ClaudeCageAnd/app/src/test/java/com/example/claudecageand/security/AntiFingerprintHardenerTest.kt).
2. **Артефакт сборки (`./gradlew assembleDebug`):**
   - Собран файл: [**`ClaudeCage-1.4.apk`**](file:///home/milk13/IdeaProjects/ClaudeCageAnd/ClaudeCage-1.4.apk) (`versionCode = 5`, `versionName = "1.4"`).
   - Расположен в корне репозитория для прямой установки на устройство через `adb install -r ClaudeCage-1.4.apk`.
