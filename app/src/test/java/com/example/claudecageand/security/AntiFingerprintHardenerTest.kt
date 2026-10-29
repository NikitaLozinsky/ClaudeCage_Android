package com.example.claudecageand.security

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

        assertTrue("Must reference __claudeCageOffline", js.contains("__claudeCageOffline"))
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

    @Test
    fun documentStartJs_w3cNotificationApiPolyfillInjectedAndCloaked() {
        val js = AntiFingerprintHardener.DOCUMENT_START_JS

        // Polyfill presence
        assertTrue("Must declare Notification constructor", js.contains("function Notification(title, options)"))
        assertTrue("Must define Notification.permission getter", js.contains("Object.defineProperty(Notification, 'permission'"))
        assertTrue("Must define Notification.requestPermission", js.contains("Notification.requestPermission = cloak("))
        assertTrue("Must define Notification.maxActions", js.contains("Notification.maxActions = 2"))
        assertTrue("Must wire ClaudeCageNotificationBridge", js.contains("window.ClaudeCageNotificationBridge"))
        assertTrue("Must wire __dispatchNotificationClick", js.contains("window.__dispatchNotificationClick = function(id)"))

        // Cloaking
        assertTrue("Must cloak Notification constructor", js.contains("cloak(Notification, 'Notification')"))
        assertTrue("Must cloak requestPermission", js.contains("'requestPermission'"))
        assertTrue("Must cloak Notification.prototype.close", js.contains("'close'"))

        // ServiceWorker & Permissions API
        assertTrue("Must polyfill ServiceWorkerRegistration showNotification", js.contains("ServiceWorkerRegistration.prototype.showNotification = cloak("))
        assertTrue("Must intercept navigator.permissions.query", js.contains("navigator.permissions.query = cloak("))
    }

    @Test
    fun documentStartJs_audioAndWebGlNoiseInjected() {
        val js = AntiFingerprintHardener.DOCUMENT_START_JS

        // AudioBuffer noise
        assertTrue("Must hook AudioBuffer.prototype.getChannelData", js.contains("AudioBuffer.prototype.getChannelData"))
        assertTrue("Must inject micro-noise to AudioBuffer channel", js.contains("1e-7 * NOISE_OFFSET"))
        assertTrue("Must track noisy buffers in WeakSet for idempotency", js.contains("noisyAudioBuffers = new WeakSet()"))

        // WebGL readPixels noise
        assertTrue("Must hook WebGLRenderingContext readPixels", js.contains("hookWebGLReadPixels(WebGLRenderingContext.prototype)"))
        assertTrue("Must hook WebGL2RenderingContext readPixels", js.contains("hookWebGLReadPixels(WebGL2RenderingContext.prototype)"))
        assertTrue("Must inject micro-noise to readPixels", js.contains("(pixels[i] + NOISE_OFFSET) % 256"))
    }

    @Test
    fun documentStartJs_clientHintsUserAgentDataSpoofed() {
        val js = AntiFingerprintHardener.DOCUMENT_START_JS

        assertTrue("Must define navigator.userAgentData", js.contains("userAgentData"))
        assertTrue("Must provide getHighEntropyValues", js.contains("getHighEntropyValues"))
        assertTrue("Must report Google Chrome brand", js.contains("Google Chrome"))
        assertTrue("Must report Chromium brand", js.contains("Chromium"))
        assertTrue("Must report Android platform", js.contains("Android"))
        assertTrue("Must report target device model SM-S938B", js.contains("SM-S938B"))
    }
}
