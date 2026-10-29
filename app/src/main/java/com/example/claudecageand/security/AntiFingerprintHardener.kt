package com.example.claudecageand.security

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

                // 7.1 AudioBuffer getChannelData Idempotent Micro-Noise
                if (window.AudioBuffer && AudioBuffer.prototype.getChannelData) {
                    const noisyAudioBuffers = new WeakSet();
                    const origGetChannelData = AudioBuffer.prototype.getChannelData;
                    AudioBuffer.prototype.getChannelData = cloak(function(channel) {
                        const buffer = origGetChannelData.call(this, channel);
                        if (buffer && buffer.length > 0 && !noisyAudioBuffers.has(buffer)) {
                            noisyAudioBuffers.add(buffer);
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
                    get: () => (window.__claudeCageOffline === true ? false : true),
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

            // 10.5 Spoof User-Agent Client Hints (navigator.userAgentData) to hide Android WebView brand
            try {
                const uaMatch = navigator.userAgent.match(/Chrome\/(\d+)(\.\d+\.\d+\.\d+)?/);
                const majorVer = uaMatch ? uaMatch[1] : '155';
                const fullVer = uaMatch && uaMatch[2] ? (uaMatch[1] + uaMatch[2]) : (majorVer + '.0.0.0');
                const brandsList = Object.freeze([
                    Object.freeze({ brand: 'Not_A Brand', version: '24' }),
                    Object.freeze({ brand: 'Chromium', version: majorVer }),
                    Object.freeze({ brand: 'Google Chrome', version: majorVer })
                ]);
                const fullVersionList = Object.freeze([
                    Object.freeze({ brand: 'Not_A Brand', version: '24.0.0.0' }),
                    Object.freeze({ brand: 'Chromium', version: fullVer }),
                    Object.freeze({ brand: 'Google Chrome', version: fullVer })
                ]);
                const fakeUaData = Object.freeze({
                    brands: brandsList,
                    mobile: true,
                    platform: 'Android',
                    toJSON: cloak(function() {
                        return { brands: this.brands, mobile: this.mobile, platform: this.platform };
                    }, 'toJSON'),
                    getHighEntropyValues: cloak(function(hints) {
                        return Promise.resolve({
                            brands: brandsList,
                            mobile: true,
                            platform: 'Android',
                            platformVersion: '16.0.0',
                            architecture: 'arm',
                            bitness: '64',
                            model: 'SM-S938B',
                            uaFullVersion: fullVer,
                            fullVersionList: fullVersionList
                        });
                    }, 'getHighEntropyValues')
                });
                Object.defineProperty(navigator, 'userAgentData', {
                    get: cloak(() => fakeUaData, 'get userAgentData'),
                    configurable: false
                });
            } catch (e) {}

            // 11. W3C Web Notification API Polyfill & Native Bridge
            try {
                let activeNotificationId = 0;
                window.__activeNotifications = window.__activeNotifications || {};

                function Notification(title, options) {
                    if (!(this instanceof Notification)) {
                        throw new TypeError("Failed to construct 'Notification': Please use the 'new' operator.");
                    }
                    if (arguments.length === 0) {
                        throw new TypeError("Failed to construct 'Notification': 1 argument required, but only 0 present.");
                    }

                    const self = this;
                    const notifId = ++activeNotificationId;
                    const opts = options || {};

                    this.title = String(title);
                    this.body = opts.body ? String(opts.body) : '';
                    this.tag = opts.tag ? String(opts.tag) : ('notif_' + notifId);
                    this.icon = opts.icon ? String(opts.icon) : '';
                    this.data = opts.data !== undefined ? opts.data : null;
                    this.silent = Boolean(opts.silent);
                    this.timestamp = Date.now();

                    this.onclick = null;
                    this.onshow = null;
                    this.onerror = null;
                    this.onclose = null;

                    this._listeners = {};
                    this.addEventListener = cloak(function(type, listener) {
                        if (typeof listener !== 'function') return;
                        self._listeners[type] = self._listeners[type] || [];
                        self._listeners[type].push(listener);
                    }, 'addEventListener');

                    this.removeEventListener = cloak(function(type, listener) {
                        if (!self._listeners[type]) return;
                        self._listeners[type] = self._listeners[type].filter(l => l !== listener);
                    }, 'removeEventListener');

                    this.dispatchEvent = cloak(function(event) {
                        const type = event && event.type;
                        if (!type) return false;
                        const handler = self['on' + type];
                        if (typeof handler === 'function') {
                            try { handler.call(self, event); } catch (e) {}
                        }
                        const list = self._listeners[type];
                        if (list) {
                            list.forEach(l => {
                                try { l.call(self, event); } catch (e) {}
                            });
                        }
                        return true;
                    }, 'dispatchEvent');

                    this.close = cloak(function() {
                        try {
                            if (window.ClaudeCageNotificationBridge) {
                                window.ClaudeCageNotificationBridge.cancelNotification(self.tag, notifId);
                            }
                        } catch (e) {}
                        delete window.__activeNotifications[notifId];
                        self.dispatchEvent(new Event('close'));
                    }, 'close');

                    window.__activeNotifications[notifId] = this;

                    try {
                        if (window.ClaudeCageNotificationBridge) {
                            window.ClaudeCageNotificationBridge.showNotification(
                                notifId,
                                this.title,
                                this.body,
                                this.tag,
                                this.icon,
                                this.silent
                            );
                        }
                    } catch (e) {
                        setTimeout(() => {
                            self.dispatchEvent(new Event('error'));
                        }, 0);
                        return;
                    }

                    setTimeout(() => {
                        self.dispatchEvent(new Event('show'));
                    }, 50);
                }

                const getPerm = cloak(function() {
                    try {
                        if (window.ClaudeCageNotificationBridge) {
                            return window.ClaudeCageNotificationBridge.getPermissionStatus();
                        }
                        return 'granted';
                    } catch (e) {
                        return 'granted';
                    }
                }, 'get permission');

                Object.defineProperty(Notification, 'permission', {
                    get: getPerm,
                    enumerable: true,
                    configurable: true
                });

                Notification.maxActions = 2;

                window._pendingPermRequests = window._pendingPermRequests || {};

                Notification.requestPermission = cloak(function(callback) {
                    return new Promise((resolve) => {
                        const reqId = 'perm_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
                        window._pendingPermRequests[reqId] = (status) => {
                            if (typeof callback === 'function') {
                                try { callback(status); } catch (e) {}
                            }
                            resolve(status);
                        };
                        try {
                            if (window.ClaudeCageNotificationBridge) {
                                window.ClaudeCageNotificationBridge.requestPermission(reqId);
                            } else {
                                window._pendingPermRequests[reqId]('granted');
                            }
                        } catch (e) {
                            window._pendingPermRequests[reqId]('granted');
                        }
                    });
                }, 'requestPermission');

                cloak(Notification, 'Notification');
                Notification.prototype.constructor = Notification;

                window.Notification = Notification;

                // Dispatched from Android MainActivity on notification click
                window.__dispatchNotificationClick = function(id) {
                    const notif = window.__activeNotifications[id];
                    if (notif) {
                        const ev = new Event('click');
                        if (typeof notif.onclick === 'function') {
                            try { notif.onclick(ev); } catch (e) {}
                        }
                        notif.dispatchEvent(ev);
                    }
                };

                // ServiceWorker showNotification polyfill
                if (typeof ServiceWorkerRegistration !== 'undefined') {
                    if (!ServiceWorkerRegistration.prototype.showNotification) {
                        ServiceWorkerRegistration.prototype.showNotification = cloak(function(title, options) {
                            new Notification(title, options);
                            return Promise.resolve();
                        }, 'showNotification');
                    }
                    if (!ServiceWorkerRegistration.prototype.getNotifications) {
                        ServiceWorkerRegistration.prototype.getNotifications = cloak(function(options) {
                            return Promise.resolve([]);
                        }, 'getNotifications');
                    }
                }

                // Permissions API query interception for 'notifications'
                if (navigator.permissions && navigator.permissions.query) {
                    const origQuery = navigator.permissions.query;
                    navigator.permissions.query = cloak(function(desc) {
                        if (desc && desc.name === 'notifications') {
                            const perm = Notification.permission;
                            const stateVal = perm === 'granted' ? 'granted' : (perm === 'denied' ? 'denied' : 'prompt');
                            return Promise.resolve({
                                state: stateVal,
                                name: 'notifications',
                                onchange: null,
                                addEventListener: function() {},
                                removeEventListener: function() {},
                                dispatchEvent: function() { return false; }
                            });
                        }
                        return origQuery.call(this, desc);
                    }, 'query');
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
