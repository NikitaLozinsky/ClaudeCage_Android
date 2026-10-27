package com.example.claudecageand.notifications

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ClaudeCageNotificationBridgeTest {

    @Test
    fun isOriginPermitted_allowsClaudeAndAnthropicOrigins() {
        assertTrue(ClaudeCageNotificationBridge.isOriginPermitted("https://claude.ai"))
        assertTrue(ClaudeCageNotificationBridge.isOriginPermitted("https://claude.ai/"))
        assertTrue(ClaudeCageNotificationBridge.isOriginPermitted("https://claude.ai/chat/abc-123"))
        assertTrue(ClaudeCageNotificationBridge.isOriginPermitted("https://anthropic.com"))
        assertTrue(ClaudeCageNotificationBridge.isOriginPermitted("https://anthropic.com/research"))
        assertTrue(ClaudeCageNotificationBridge.isOriginPermitted("https://claude.com"))
    }

    @Test
    fun isOriginPermitted_rejectsUnauthorizedOrigins() {
        assertFalse(ClaudeCageNotificationBridge.isOriginPermitted("https://google.com"))
        assertFalse(ClaudeCageNotificationBridge.isOriginPermitted("https://evil-claude.ai"))
        assertFalse(ClaudeCageNotificationBridge.isOriginPermitted("http://claude.ai"))
        assertFalse(ClaudeCageNotificationBridge.isOriginPermitted("https://claude.ai.attacker.com"))
        assertFalse(ClaudeCageNotificationBridge.isOriginPermitted(""))
        assertFalse(ClaudeCageNotificationBridge.isOriginPermitted(null))
    }

    @Test
    fun constants_verifyChannelAndExtra() {
        assertTrue(ClaudeCageNotificationBridge.CHANNEL_ID == "claude_cage_notifications")
        assertTrue(ClaudeCageNotificationBridge.EXTRA_NOTIFICATION_ID == "extra_claude_notification_id")
    }
}
