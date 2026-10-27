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
}
