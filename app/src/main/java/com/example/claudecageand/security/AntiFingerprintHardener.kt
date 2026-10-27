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

                const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
                CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh, settings) {
                    const imgData = origGetImageData.call(this, sx, sy, sw, sh, settings);
                    if (imgData && imgData.data && imgData.data.length >= 4) {
                        imgData.data[0] = (imgData.data[0] + NOISE_OFFSET) % 256;
                    }
                    return imgData;
                };

                const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
                HTMLCanvasElement.prototype.toDataURL = function(type, encoderOptions) {
                    try {
                        const ctx = this.getContext('2d');
                        if (ctx && this.width > 0 && this.height > 0) {
                            const pixel = origGetImageData.call(ctx, 0, 0, 1, 1);
                            pixel.data[0] = (pixel.data[0] + NOISE_OFFSET) % 256;
                            ctx.putImageData(pixel, 0, 0);
                        }
                    } catch (e) {}
                    return origToDataURL.call(this, type, encoderOptions);
                };

                const origToBlob = HTMLCanvasElement.prototype.toBlob;
                HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
                    try {
                        const ctx = this.getContext('2d');
                        if (ctx && this.width > 0 && this.height > 0) {
                            const pixel = origGetImageData.call(ctx, 0, 0, 1, 1);
                            pixel.data[0] = (pixel.data[0] + NOISE_OFFSET) % 256;
                            ctx.putImageData(pixel, 0, 0);
                        }
                    } catch (e) {}
                    return origToBlob.call(this, callback, type, quality);
                };
            } catch (e) {}
        """.trimIndent()

        return """
        (() => {
            'use strict';

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
                Date.prototype.getTimezoneOffset = function() {
                    return computeAmsterdamOffset(this);
                };
            } catch (e) {}

            try {
                const OrigDTF = Intl.DateTimeFormat;
                const ProxyDTF = function(locales, options) {
                    const opts = Object.assign({}, options);
                    if (!opts.timeZone) {
                        opts.timeZone = TARGET_TIMEZONE;
                    }
                    return new OrigDTF(locales || 'en-US', opts);
                };
                ProxyDTF.prototype = OrigDTF.prototype;
                ProxyDTF.supportedLocalesOf = OrigDTF.supportedLocalesOf;

                const origResolvedOptions = OrigDTF.prototype.resolvedOptions;
                OrigDTF.prototype.resolvedOptions = function() {
                    const res = origResolvedOptions.call(this);
                    res.timeZone = TARGET_TIMEZONE;
                    return res;
                };

                Intl.DateTimeFormat = ProxyDTF;
            } catch (e) {}

            // 5. Date string representations in Europe/Amsterdam (en-US)
            try {
                Date.prototype.toString = function() {
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
                };

                Date.prototype.toTimeString = function() {
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
                };

                const origToLocaleString = Date.prototype.toLocaleString;
                Date.prototype.toLocaleString = function(locales, options) {
                    const opts = Object.assign({}, options);
                    if (!opts.timeZone) opts.timeZone = TARGET_TIMEZONE;
                    return origToLocaleString.call(this, locales || 'en-US', opts);
                };

                const origToLocaleDateString = Date.prototype.toLocaleDateString;
                Date.prototype.toLocaleDateString = function(locales, options) {
                    const opts = Object.assign({}, options);
                    if (!opts.timeZone) opts.timeZone = TARGET_TIMEZONE;
                    return origToLocaleDateString.call(this, locales || 'en-US', opts);
                };

                const origToLocaleTimeString = Date.prototype.toLocaleTimeString;
                Date.prototype.toLocaleTimeString = function(locales, options) {
                    const opts = Object.assign({}, options);
                    if (!opts.timeZone) opts.timeZone = TARGET_TIMEZONE;
                    return origToLocaleTimeString.call(this, locales || 'en-US', opts);
                };
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
            if (window.speechSynthesis) {
                try {
                    window.speechSynthesis.getVoices = () => [];
                    window.speechSynthesis.onvoiceschanged = null;
                } catch (e) {}
            }

            // 9. Lock All Intl Constructors resolvedOptions to en-US
            try {
                const lockLocale = (proto) => {
                    if (proto && proto.resolvedOptions) {
                        const orig = proto.resolvedOptions;
                        proto.resolvedOptions = function() {
                            const res = orig.call(this);
                            if (res) res.locale = 'en-US';
                            return res;
                        };
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
