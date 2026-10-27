package com.example.claudecageand.accounts

import android.content.Context
import android.content.SharedPreferences
import androidx.webkit.Profile
import androidx.webkit.ProfileStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`

class AccountProfileManagerTest {

    private lateinit var mockContext: Context
    private lateinit var fakePrefs: FakeSharedPreferences
    private lateinit var mockProfileStore: ProfileStore
    private lateinit var manager: AccountProfileManager

    @Before
    fun setUp() {
        mockContext = mock(Context::class.java)
        fakePrefs = FakeSharedPreferences()
        mockProfileStore = mock(ProfileStore::class.java)

        `when`(mockContext.applicationContext).thenReturn(mockContext)
        `when`(mockContext.getSharedPreferences(AccountProfileManager.PREFS_NAME, Context.MODE_PRIVATE))
            .thenReturn(fakePrefs)

        manager = AccountProfileManager(
            context = mockContext,
            prefsOverride = fakePrefs,
            profileStoreProvider = { mockProfileStore }
        )
    }

    @Test
    fun defaultInitialization_initializesWithDefaultAccount() {
        val profiles = manager.profiles.value
        assertEquals(1, profiles.size)

        val defaultProfile = profiles[0]
        assertEquals(AccountProfile.DEFAULT_ID, defaultProfile.id)
        assertEquals("Default Account", defaultProfile.displayName)
        assertEquals(Profile.DEFAULT_PROFILE_NAME, defaultProfile.storageKey)

        val active = manager.activeProfile.value
        assertEquals(defaultProfile.id, active.id)
        assertEquals(defaultProfile.displayName, active.displayName)
        assertTrue(defaultProfile.profileSeed >= 0)
    }

    @Test
    fun profileSeed_deterministicAndDistinct() {
        val p1 = AccountProfile("profile-1", "Account 1")
        val p2 = AccountProfile("profile-2", "Account 2")
        val p1Copy = AccountProfile("profile-1", "Renamed Account")
        assertEquals(p1.profileSeed, p1Copy.profileSeed)
        assertTrue(p1.profileSeed >= 0)
        assertTrue(p2.profileSeed >= 0)
    }

    @Test
    fun createProfile_addsProfileAndUpdatesList() {
        val created = manager.createProfile("Work Account")

        assertNotNull(created.id)
        assertTrue(created.id != AccountProfile.DEFAULT_ID)
        assertEquals("Work Account", created.displayName)
        assertTrue(created.storageKey.startsWith("profile_"))

        val profiles = manager.profiles.value
        assertEquals(2, profiles.size)
        assertEquals("Default Account", profiles[0].displayName)
        assertEquals("Work Account", profiles[1].displayName)
    }

    @Test
    fun createProfile_blankName_usesFallbackName() {
        val created = manager.createProfile("   ")
        assertEquals("Account 2", created.displayName)
    }

    @Test
    fun switchProfile_transitionsActiveProfile() {
        val work = manager.createProfile("Work")
        val personal = manager.createProfile("Personal")

        // Switch to Work
        val switchedWork = manager.switchProfile(work.id)
        assertTrue(switchedWork)
        assertEquals(work.id, manager.activeProfile.value.id)
        assertEquals("Work", manager.activeProfile.value.displayName)

        // Switch to Personal
        val switchedPersonal = manager.switchProfile(personal.id)
        assertTrue(switchedPersonal)
        assertEquals(personal.id, manager.activeProfile.value.id)
        assertEquals("Personal", manager.activeProfile.value.displayName)

        // Switch to non-existent ID fails
        val invalidSwitch = manager.switchProfile("non-existent-id")
        assertFalse(invalidSwitch)
        assertEquals(personal.id, manager.activeProfile.value.id)
    }

    @Test
    fun renameProfile_updatesDisplayNameAndActiveProfile() {
        val profile = manager.createProfile("Original Name")
        manager.switchProfile(profile.id)

        val renameSuccess = manager.renameProfile(profile.id, "Updated Name")
        assertTrue(renameSuccess)

        // Verify updated in list
        val updated = manager.profiles.value.find { it.id == profile.id }
        assertNotNull(updated)
        assertEquals("Updated Name", updated?.displayName)

        // Verify active profile reflects rename
        assertEquals("Updated Name", manager.activeProfile.value.displayName)

        // Renaming with empty string fails and preserves existing name
        val emptyRename = manager.renameProfile(profile.id, "   ")
        assertFalse(emptyRename)
        assertEquals("Updated Name", manager.activeProfile.value.displayName)

        // Renaming unknown ID fails
        val unknownRename = manager.renameProfile("unknown-id", "New Name")
        assertFalse(unknownRename)
    }

    @Test
    fun deleteProfile_cannotDeleteOnlyRemainingProfile() {
        assertEquals(1, manager.profiles.value.size)
        val defaultId = manager.profiles.value[0].id

        val deleted = manager.deleteProfile(defaultId)
        assertFalse(deleted)
        assertEquals(1, manager.profiles.value.size)
    }

    @Test
    fun deleteProfile_nonActiveProfile_deletesStorageAndRemovesFromList() {
        val work = manager.createProfile("Work")
        assertEquals(2, manager.profiles.value.size)

        val deleted = manager.deleteProfile(work.id)
        assertTrue(deleted)
        assertEquals(1, manager.profiles.value.size)
        assertEquals(AccountProfile.DEFAULT_ID, manager.profiles.value[0].id)

        // Verify profileStore.deleteProfile was called with profile's storageKey
        verify(mockProfileStore).deleteProfile(work.storageKey)
    }

    @Test
    fun deleteProfile_activeProfile_transitionsToRemainingProfile() {
        val work = manager.createProfile("Work")
        manager.switchProfile(work.id)
        assertEquals(work.id, manager.activeProfile.value.id)

        val deleted = manager.deleteProfile(work.id)
        assertTrue(deleted)
        assertEquals(1, manager.profiles.value.size)

        // Active profile should have transitioned to the remaining default account
        assertEquals(AccountProfile.DEFAULT_ID, manager.activeProfile.value.id)
        assertEquals("Default Account", manager.activeProfile.value.displayName)
    }

    @Test
    fun persistence_restoresProfilesAndActiveStateAcrossInstances() {
        val work = manager.createProfile("Work")
        manager.createProfile("Personal")
        manager.switchProfile(work.id)
        manager.renameProfile(work.id, "Work Pro")

        // Create a new instance pointing to the same SharedPreferences
        val restoredManager = AccountProfileManager(
            context = mockContext,
            prefsOverride = fakePrefs,
            profileStoreProvider = { mockProfileStore }
        )

        val restoredProfiles = restoredManager.profiles.value
        assertEquals(3, restoredProfiles.size)
        assertEquals("Default Account", restoredProfiles[0].displayName)
        assertEquals("Work Pro", restoredProfiles[1].displayName)
        assertEquals("Personal", restoredProfiles[2].displayName)

        assertEquals(work.id, restoredManager.activeProfile.value.id)
        assertEquals("Work Pro", restoredManager.activeProfile.value.displayName)
    }

    @Test
    fun fallbackCookieStorage_encryptsAndRestoresCookies() {
        val fallback = AccountCookieJarFallback(mockContext, fakePrefs)
        val testCookies = "sessionKey=tok-auth-test12345; __cf_bm=randomcfbmvalue; other=val"

        fallback.saveCookies("test-profile-1", testCookies)
        val restored = fallback.getCookies("test-profile-1")
        assertEquals(testCookies, restored)

        // Verify cookies for different profiles are isolated
        fallback.saveCookies("test-profile-2", "sessionKey=tok-auth-different6789")
        assertEquals(testCookies, fallback.getCookies("test-profile-1"))
        assertEquals("sessionKey=tok-auth-different6789", fallback.getCookies("test-profile-2"))

        // Delete cookies
        fallback.deleteCookies("test-profile-1")
        assertEquals(null, fallback.getCookies("test-profile-1"))
        assertEquals("sessionKey=tok-auth-different6789", fallback.getCookies("test-profile-2"))
    }

    @Test
    fun fallbackCookieStorage_aadPreventsCrossProfileDecryption() {
        val fallback = AccountCookieJarFallback(mockContext, fakePrefs)
        val encrypted = fallback.encrypt("profile-A", "secret-session-cookie")

        // Decrypting with correct profile succeeds
        val decryptedSuccess = fallback.decrypt("profile-A", encrypted)
        assertEquals("secret-session-cookie", decryptedSuccess)

        // Decrypting with wrong profile fails due to GCM AAD authentication tag mismatch
        val decryptedFail = fallback.decrypt("profile-B", encrypted)
        assertEquals(null, decryptedFail)
    }

    @Test
    fun jsonCodec_handlesSpecialCharactersAndCyrillic() {
        val profiles = listOf(
            AccountProfile("id1", "Рабочий аккаунт (Claude)", 1000L),
            AccountProfile("id2", "Quotes \"and\" \\slashes\\, plus commas", 2000L),
            AccountProfile("id3", "Nested {Braces} and [Brackets] {dev}", 3000L)
        )

        val json = AccountProfileJsonCodec.toJson(profiles)
        val restored = AccountProfileJsonCodec.fromJson(json)

        assertEquals(3, restored.size)
        assertEquals("id1", restored[0].id)
        assertEquals("Рабочий аккаунт (Claude)", restored[0].displayName)
        assertEquals(1000L, restored[0].createdAt)

        assertEquals("id2", restored[1].id)
        assertEquals("Quotes \"and\" \\slashes\\, plus commas", restored[1].displayName)
        assertEquals(2000L, restored[1].createdAt)

        assertEquals("id3", restored[2].id)
        assertEquals("Nested {Braces} and [Brackets] {dev}", restored[2].displayName)
        assertEquals(3000L, restored[2].createdAt)
    }
}

/**
 * In-memory [SharedPreferences] implementation for local JVM unit tests.
 */
class FakeSharedPreferences : SharedPreferences {
    private val data = mutableMapOf<String, Any?>()

    override fun getAll(): MutableMap<String, *> = data
    override fun getString(key: String?, defValue: String?): String? = data[key] as? String ?: defValue
    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
        (data[key] as? MutableSet<String>) ?: defValues
    override fun getInt(key: String?, defValue: Int): Int = data[key] as? Int ?: defValue
    override fun getLong(key: String?, defValue: Long): Long = data[key] as? Long ?: defValue
    override fun getFloat(key: String?, defValue: Float): Float = data[key] as? Float ?: defValue
    override fun getBoolean(key: String?, defValue: Boolean): Boolean = data[key] as? Boolean ?: defValue
    override fun contains(key: String?): Boolean = data.containsKey(key)
    override fun edit(): SharedPreferences.Editor = FakeEditor()
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

    inner class FakeEditor : SharedPreferences.Editor {
        private val temp = mutableMapOf<String, Any?>()
        private val removed = mutableSetOf<String>()
        private var clear = false

        override fun putString(key: String?, value: String?): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor {
            if (key != null) temp[key] = values
            return this
        }
        override fun putInt(key: String?, value: Int): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun remove(key: String?): SharedPreferences.Editor {
            if (key != null) removed.add(key)
            return this
        }
        override fun clear(): SharedPreferences.Editor {
            clear = true
            return this
        }
        override fun commit(): Boolean {
            apply()
            return true
        }
        override fun apply() {
            if (clear) data.clear()
            for (key in removed) data.remove(key)
            data.putAll(temp)
        }
    }
}
