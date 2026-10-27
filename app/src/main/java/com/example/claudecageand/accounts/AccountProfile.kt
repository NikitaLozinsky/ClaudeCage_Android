package com.example.claudecageand.accounts

import androidx.webkit.Profile

/**
 * Data model representing an isolated user account profile.
 *
 * @property id Unique identifier (e.g. "default" or UUID).
 * @property displayName Human-readable name (e.g. "Default Account", "Work", "Personal").
 * @property createdAt Epoch timestamp when the profile was created.
 */
data class AccountProfile(
    val id: String,
    val displayName: String,
    val createdAt: Long = System.currentTimeMillis()
) {
    val profileSeed: Int
        get() = kotlin.math.abs(id.hashCode())

    /**
     * Alphanumeric/underscore key used for AndroidX [androidx.webkit.ProfileStore].
     * Defaults to [Profile.DEFAULT_PROFILE_NAME] ("Default") for the primary profile.
     */
    val storageKey: String
        get() = if (id == DEFAULT_ID) Profile.DEFAULT_PROFILE_NAME else "profile_${id.replace("-", "_")}"

    companion object {
        const val DEFAULT_ID = "default"
        const val DEFAULT_DISPLAY_NAME = "Default Account"
    }
}
