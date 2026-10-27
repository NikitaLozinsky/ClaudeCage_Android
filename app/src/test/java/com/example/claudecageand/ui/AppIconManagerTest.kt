package com.example.claudecageand.ui

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.`when`
import org.mockito.Mockito.atLeastOnce
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify

class AppIconManagerTest {

    private val mockContext = mock(Context::class.java)
    private val mockPm = mock(PackageManager::class.java)
    private val mockPrefs = mock(SharedPreferences::class.java)
    private val mockEditor = mock(SharedPreferences.Editor::class.java)

    @Before
    fun setUp() {
        `when`(mockContext.applicationContext).thenReturn(mockContext)
        `when`(mockContext.packageManager).thenReturn(mockPm)
        `when`(mockContext.packageName).thenReturn("com.example.claudecageand")
        `when`(mockContext.getSharedPreferences(anyString(), anyInt())).thenReturn(mockPrefs)
        `when`(mockPrefs.getString(anyString(), anyString())).thenReturn("variant_1")
        `when`(mockPrefs.edit()).thenReturn(mockEditor)
        `when`(mockEditor.putString(anyString(), anyString())).thenReturn(mockEditor)
    }

    @Test
    fun defaultIcon_isVariant1() {
        val manager = AppIconManager(mockContext)
        assertEquals(AppIconOption.VARIANT_1, manager.getCurrentIcon())
    }

    @Test
    fun setAppIcon_variant2_enablesVariant2Alias() {
        val manager = AppIconManager(mockContext)
        val success = manager.setAppIcon(AppIconOption.VARIANT_2)

        assertTrue(success)
        verify(mockPm, atLeastOnce()).setComponentEnabledSetting(
            any(),
            anyInt(),
            anyInt()
        )
        verify(mockEditor).putString("selected_app_icon", "variant_2")
    }

    @Test
    fun setAppIcon_variant1_enablesDefaultAlias() {
        val manager = AppIconManager(mockContext)
        val success = manager.setAppIcon(AppIconOption.VARIANT_1)

        assertTrue(success)
        verify(mockPm, atLeastOnce()).setComponentEnabledSetting(
            any(),
            anyInt(),
            anyInt()
        )
        verify(mockEditor).putString("selected_app_icon", "variant_1")
    }
}
