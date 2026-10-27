package com.example.claudecageand.ui

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
        private const val PREFS_NAME = "claudecage_ui_prefs"
        private const val KEY_LANG = "ui_language"
    }
}
