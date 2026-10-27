package com.example.claudecageand.ui

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log

enum class AppIconOption(val key: String, val aliasClass: String) {
    VARIANT_1("variant_1", "com.example.claudecageand.MainActivityAliasDefault"),
    VARIANT_2("variant_2", "com.example.claudecageand.MainActivityAliasVariant2")
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
        private const val PREFS_NAME = "claudecage_icon_prefs"
        private const val KEY_ICON = "selected_app_icon"
    }
}
