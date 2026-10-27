package com.example.claudecageand.accounts

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.webkit.Profile
import androidx.webkit.ProfileStore
import androidx.webkit.WebViewFeature
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

/**
 * Manages user account profiles and Chromium multi-profile containerization.
 *
 * Guarantees:
 * 1. Default initialization with "Default Account".
 * 2. Persistence of profile list and active profile ID in SharedPreferences.
 * 3. Native container isolation via [ProfileStore] when MULTI_PROFILE is supported.
 * 4. Automatic web storage cleanup when a profile is deleted.
 * 5. Safeguard: cannot delete the only remaining profile.
 * 6. Fallback cookie jar storage support when MULTI_PROFILE is unavailable.
 */
class AccountProfileManager(
    context: Context,
    prefsOverride: SharedPreferences? = null,
    private val profileStoreProvider: (() -> ProfileStore?)? = null,
    cookieJarFallback: AccountCookieJarFallback? = null
) {
    private val prefs: SharedPreferences = prefsOverride
        ?: context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    val fallback: AccountCookieJarFallback = cookieJarFallback ?: AccountCookieJarFallback(context, prefsOverride)

    private val _profiles = MutableStateFlow<List<AccountProfile>>(emptyList())
    val profiles: StateFlow<List<AccountProfile>> = _profiles.asStateFlow()

    private val _activeProfile = MutableStateFlow(
        AccountProfile(AccountProfile.DEFAULT_ID, AccountProfile.DEFAULT_DISPLAY_NAME)
    )
    val activeProfile: StateFlow<AccountProfile> = _activeProfile.asStateFlow()

    init {
        loadProfiles()
    }

    @Synchronized
    private fun loadProfiles() {
        val rawJson = prefs.getString(KEY_PROFILES, null)
        val loaded = AccountProfileJsonCodec.fromJson(rawJson)
        val initialList = if (loaded.isEmpty()) {
            val defaultAcc = AccountProfile(
                id = AccountProfile.DEFAULT_ID,
                displayName = AccountProfile.DEFAULT_DISPLAY_NAME,
                createdAt = System.currentTimeMillis()
            )
            val list = listOf(defaultAcc)
            persistProfiles(list)
            list
        } else {
            loaded
        }
        _profiles.value = initialList

        val savedActiveId = prefs.getString(KEY_ACTIVE_PROFILE_ID, null)
        val active = initialList.find { it.id == savedActiveId } ?: initialList.first()
        _activeProfile.value = active
        prefs.edit().putString(KEY_ACTIVE_PROFILE_ID, active.id).apply()
    }

    @Synchronized
    fun createProfile(name: String): AccountProfile {
        val trimmed = name.trim()
        val displayName = if (trimmed.isEmpty()) {
            "Account ${_profiles.value.size + 1}"
        } else {
            trimmed
        }
        val newProfile = AccountProfile(
            id = UUID.randomUUID().toString(),
            displayName = displayName,
            createdAt = System.currentTimeMillis()
        )
        val updated = _profiles.value + newProfile
        _profiles.value = updated
        persistProfiles(updated)
        Log.i(TAG, "Created profile: ${newProfile.id} (${newProfile.displayName})")
        return newProfile
    }

    @Synchronized
    fun switchProfile(id: String): Boolean {
        val target = _profiles.value.find { it.id == id } ?: return false
        _activeProfile.value = target
        prefs.edit().putString(KEY_ACTIVE_PROFILE_ID, target.id).apply()
        Log.i(TAG, "Switched active profile to: ${target.id} (${target.displayName})")
        return true
    }

    @Synchronized
    fun renameProfile(id: String, newName: String): Boolean {
        val trimmed = newName.trim()
        if (trimmed.isEmpty()) return false
        val index = _profiles.value.indexOfFirst { it.id == id }
        if (index == -1) return false

        val updated = _profiles.value.toMutableList()
        val old = updated[index]
        val modified = old.copy(displayName = trimmed)
        updated[index] = modified
        _profiles.value = updated
        persistProfiles(updated)

        if (_activeProfile.value.id == id) {
            _activeProfile.value = modified
        }
        Log.i(TAG, "Renamed profile $id to: $trimmed")
        return true
    }

    @Synchronized
    fun deleteProfile(id: String): Boolean {
        if (_profiles.value.size <= 1) {
            Log.w(TAG, "Cannot delete only remaining profile: $id")
            return false
        }
        val target = _profiles.value.find { it.id == id } ?: return false

        // Delete web storage via ProfileStore
        deleteProfileStorage(target)

        // Delete fallback cookies if any
        fallback.deleteCookies(target.id)

        val updated = _profiles.value.filter { it.id != id }
        _profiles.value = updated
        persistProfiles(updated)

        // If deleted profile was active, transition to first remaining profile
        if (_activeProfile.value.id == id) {
            val newActive = updated.first()
            _activeProfile.value = newActive
            prefs.edit().putString(KEY_ACTIVE_PROFILE_ID, newActive.id).apply()
            Log.i(TAG, "Active profile was deleted, transitioned to: ${newActive.displayName}")
        }
        Log.i(TAG, "Deleted profile: ${target.id} (${target.displayName})")
        return true
    }

    private fun deleteProfileStorage(profile: AccountProfile) {
        try {
            val store = getProfileStore()
            if (store != null) {
                if (profile.storageKey == Profile.DEFAULT_PROFILE_NAME) {
                    val p = runCatching { store.getProfile(profile.storageKey) }.getOrNull()
                    p?.webStorage?.deleteAllData()
                    p?.cookieManager?.removeAllCookies(null)
                } else {
                    store.deleteProfile(profile.storageKey)
                }
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Failed to delete storage for ${profile.storageKey}: ${e.message}")
        }
    }

    private fun getProfileStore(): ProfileStore? {
        return profileStoreProvider?.invoke() ?: try {
            if (WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) {
                ProfileStore.getInstance()
            } else {
                null
            }
        } catch (e: Throwable) {
            null
        }
    }

    private fun persistProfiles(list: List<AccountProfile>) {
        val json = AccountProfileJsonCodec.toJson(list)
        prefs.edit().putString(KEY_PROFILES, json).apply()
    }

    companion object {
        private const val TAG = "AccountProfileManager"
        const val PREFS_NAME = "claudecage_accounts_prefs"
        const val KEY_PROFILES = "profiles_list"
        const val KEY_ACTIVE_PROFILE_ID = "active_profile_id"
    }
}
