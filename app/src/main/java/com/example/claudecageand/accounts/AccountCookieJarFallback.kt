package com.example.claudecageand.accounts

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
            val keyAlias = "claudecage_cookie_aes_key"
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
    fun snapshotCookies(profileId: String, url: String = CLAUDE_URL) {
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
    fun restoreCookies(targetProfileId: String, url: String = CLAUDE_URL, onComplete: (() -> Unit)? = null) {
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
        private const val PREFS_NAME = "claudecage_cookie_jar_prefs"
        private const val KEY_SECRET_KEY = "jar_aes_key"
        private const val KEY_COOKIE_PREFIX = "jar_cookies_"
        const val CLAUDE_URL = "https://claude.ai"
    }
}
