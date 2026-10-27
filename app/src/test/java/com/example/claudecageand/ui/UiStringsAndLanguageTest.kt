package com.example.claudecageand.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UiStringsAndLanguageTest {

    @Test
    fun uiStrings_allSectionsDefinedForBothLanguages() {
        val languages = listOf(UiLanguage.RU, UiLanguage.EN)

        for (lang in languages) {
            assertTrue(UiStrings.statusActive(lang, "tun0", "10.0.0.1", 12345).isNotBlank())
            assertTrue(UiStrings.statusOffline(lang, 12345).isNotBlank())
            assertTrue(UiStrings.statusConnectionLost(lang).isNotBlank())
            assertTrue(UiStrings.statusRestored(lang).isNotBlank())
            assertTrue(UiStrings.waitingTitle(lang).isNotBlank())
            assertTrue(UiStrings.waitingDesc(lang).isNotBlank())
            assertTrue(UiStrings.securityErrorTitle(lang).isNotBlank())
            assertTrue(UiStrings.securityErrorDesc(lang).isNotBlank())

            // 5 Dashboard Sections
            assertTrue(UiStrings.diagDialogTitle(lang).isNotBlank())
            assertTrue(UiStrings.sectionKillSwitchTitle(lang).isNotBlank())
            assertTrue(UiStrings.killSwitchProtected(lang).isNotBlank())
            assertTrue(UiStrings.killSwitchBlocked(lang).isNotBlank())
            assertTrue(UiStrings.killSwitchExplanation(lang).isNotBlank())

            assertTrue(UiStrings.sectionTunnelTitle(lang).isNotBlank())
            assertTrue(UiStrings.tunnelNoActive(lang).isNotBlank())
            assertTrue(UiStrings.tunnelExplanation(lang).isNotBlank())

            assertTrue(UiStrings.sectionProxyTitle(lang).isNotBlank())
            assertTrue(UiStrings.proxyStatus(lang, 9050).isNotBlank())
            assertTrue(UiStrings.proxyExplanation(lang).isNotBlank())

            assertTrue(UiStrings.sectionDnsTitle(lang).isNotBlank())
            assertTrue(UiStrings.dnsStatus(lang, 5, 0).isNotBlank())
            assertTrue(UiStrings.dnsExplanation(lang).isNotBlank())

            assertTrue(UiStrings.sectionFingerprintTitle(lang).isNotBlank())
            assertTrue(UiStrings.fingerprintStatus(lang).isNotBlank())
            assertTrue(UiStrings.fingerprintExplanation(lang).isNotBlank())

            // Buttons
            assertTrue(UiStrings.btnCopyAiReport(lang).isNotBlank())
            assertTrue(UiStrings.btnShareLog(lang).isNotBlank())
            assertTrue(UiStrings.btnBrowserLeaks(lang).isNotBlank())
            assertTrue(UiStrings.btnClearLogs(lang).isNotBlank())
            assertTrue(UiStrings.btnChangeIcon(lang).isNotBlank())
            assertTrue(UiStrings.dialogChooseIconTitle(lang).isNotBlank())
            assertTrue(UiStrings.iconVariant1(lang).isNotBlank())
            assertTrue(UiStrings.iconVariant2(lang).isNotBlank())
            assertTrue(UiStrings.toastIconChanged(lang).isNotBlank())
            assertTrue(UiStrings.btnClose(lang).isNotBlank())

            // Multi-Account strings (Stage 7)
            assertTrue(UiStrings.btnAccountSelector(lang, "Work").isNotBlank())
            assertTrue(UiStrings.accountDialogTitle(lang).isNotBlank())
            assertTrue(UiStrings.btnAddAccount(lang).isNotBlank())
            assertTrue(UiStrings.dialogAddAccountTitle(lang).isNotBlank())
            assertTrue(UiStrings.dialogAddAccountHint(lang).isNotBlank())
            assertTrue(UiStrings.dialogRenameTitle(lang).isNotBlank())
            assertTrue(UiStrings.dialogDeleteConfirmTitle(lang).isNotBlank())
            assertTrue(UiStrings.dialogDeleteConfirmMessage(lang, "Work").isNotBlank())
            assertTrue(UiStrings.dialogDeleteCannotDeleteOnly(lang).isNotBlank())
            assertTrue(UiStrings.btnAdd(lang).isNotBlank())
            assertTrue(UiStrings.btnRename(lang).isNotBlank())
            assertTrue(UiStrings.btnDelete(lang).isNotBlank())
            assertTrue(UiStrings.btnCancel(lang).isNotBlank())
            assertTrue(UiStrings.btnSave(lang).isNotBlank())
            assertTrue(UiStrings.toastProfileSwitched(lang, "Work").isNotBlank())
            assertTrue(UiStrings.toastProfileCreated(lang, "Work").isNotBlank())
            assertTrue(UiStrings.toastProfileDeleted(lang, "Work").isNotBlank())
            assertTrue(UiStrings.toastProfileRenamed(lang).isNotBlank())
            assertTrue(UiStrings.activeAccountBadge(lang).isNotBlank())

            // Floating Anchor & Minimalist Status strings
            assertTrue(UiStrings.sectionVersionsTitle(lang).isNotBlank())
            assertTrue(UiStrings.btnVersions(lang).isNotBlank())
            assertTrue(UiStrings.dialogVersionsTitle(lang).isNotBlank())
            assertTrue(UiStrings.btnCopyVersions(lang).isNotBlank())
            assertTrue(UiStrings.toastVersionsCopied(lang).isNotBlank())
            assertTrue(UiStrings.statusProtectedConcise(lang).isNotBlank())
            assertTrue(UiStrings.statusBlockedConcise(lang).isNotBlank())
            assertTrue(UiStrings.statusLeakRiskConcise(lang).isNotBlank())
            assertTrue(UiStrings.subStatusActive(lang, "tun0", 9050).isNotBlank())
            assertTrue(UiStrings.subStatusOffline(lang, 9050).isNotBlank())
        }
    }

    @Test
    fun uiLanguage_togglesCorrectly() {
        assertEquals("RU", UiLanguage.RU.label)
        assertEquals("EN", UiLanguage.EN.label)
    }
}
