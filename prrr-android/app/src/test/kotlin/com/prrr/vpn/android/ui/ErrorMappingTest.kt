// FRD: specs/frds/FRD-M013-settings-battery-errors.md
package com.prrr.vpn.android.ui

import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull

/**
 * Tests for error-to-user-message mapping.
 * Verifies that each MobileError variant maps to the correct
 * user-facing title, message, and optional retry action text.
 *
 * Mutant killed per test: wrong title/message/action for a given error variant.
 * Contract: ErrorContent must provide non-empty title and message for every variant.
 */
class ErrorMappingTest {

    @Test
    fun `InvalidConfig maps to correct title`() {
        // Mutant killed: wrong title for InvalidConfig
        val content = ErrorContent.fromInvalidConfig()
        assertEquals("Invalid Configuration", content.title)
    }

    @Test
    fun `InvalidConfig maps to correct message`() {
        // Mutant killed: wrong message for InvalidConfig
        val content = ErrorContent.fromInvalidConfig()
        assertEquals(
            "The QR code or configuration is invalid. Please scan a valid prrr VPN QR code.",
            content.message
        )
    }

    @Test
    fun `InvalidConfig has no retry action`() {
        // Mutant killed: InvalidConfig incorrectly offers retry
        val content = ErrorContent.fromInvalidConfig()
        assertNull(content.retryLabel)
    }

    @Test
    fun `ConnectionFailed maps to correct title`() {
        // Mutant killed: wrong title for ConnectionFailed
        val content = ErrorContent.fromConnectionFailed()
        assertEquals("Connection Failed", content.title)
    }

    @Test
    fun `ConnectionFailed maps to correct message`() {
        // Mutant killed: wrong message for ConnectionFailed
        val content = ErrorContent.fromConnectionFailed()
        assertEquals(
            "Unable to reach the VPN server. Check your internet connection and try again.",
            content.message
        )
    }

    @Test
    fun `ConnectionFailed has retry action`() {
        // Mutant killed: ConnectionFailed missing retry action
        val content = ErrorContent.fromConnectionFailed()
        assertNotNull(content.retryLabel)
        assertEquals("Retry", content.retryLabel)
    }

    @Test
    fun `HandshakeFailed maps to correct title`() {
        // Mutant killed: wrong title for HandshakeFailed
        val content = ErrorContent.fromHandshakeFailed()
        assertEquals("Security Check Failed", content.title)
    }

    @Test
    fun `HandshakeFailed maps to correct message`() {
        // Mutant killed: wrong message for HandshakeFailed
        val content = ErrorContent.fromHandshakeFailed()
        assertEquals(
            "The server's security credentials could not be verified. Your access may have been revoked.",
            content.message
        )
    }

    @Test
    fun `HandshakeFailed has no retry action`() {
        // Mutant killed: HandshakeFailed incorrectly offers retry
        val content = ErrorContent.fromHandshakeFailed()
        assertNull(content.retryLabel)
    }

    @Test
    fun `NetworkError maps to correct title`() {
        // Mutant killed: wrong title for NetworkError
        val content = ErrorContent.fromNetworkError()
        assertEquals("Network Error", content.title)
    }

    @Test
    fun `NetworkError maps to correct message`() {
        // Mutant killed: wrong message for NetworkError
        val content = ErrorContent.fromNetworkError()
        assertEquals(
            "A network error occurred. Please check your connection and try again.",
            content.message
        )
    }

    @Test
    fun `NetworkError has retry action`() {
        // Mutant killed: NetworkError missing retry action
        val content = ErrorContent.fromNetworkError()
        assertNotNull(content.retryLabel)
        assertEquals("Retry", content.retryLabel)
    }

    @Test
    fun `TunnelFailed maps to correct title`() {
        // Mutant killed: wrong title for TunnelFailed
        val content = ErrorContent.fromTunnelFailed()
        assertEquals("Tunnel Error", content.title)
    }

    @Test
    fun `TunnelFailed maps to correct message`() {
        // Mutant killed: wrong message for TunnelFailed
        val content = ErrorContent.fromTunnelFailed()
        assertEquals(
            "The encrypted tunnel encountered an error. Please reconnect.",
            content.message
        )
    }

    @Test
    fun `TunnelFailed has retry action`() {
        // Mutant killed: TunnelFailed missing retry action
        val content = ErrorContent.fromTunnelFailed()
        assertNotNull(content.retryLabel)
        assertEquals("Retry", content.retryLabel)
    }

    @Test
    fun `NotConnected maps to correct title`() {
        // Mutant killed: wrong title for NotConnected
        val content = ErrorContent.fromNotConnected()
        assertEquals("Not Connected", content.title)
    }

    @Test
    fun `NotConnected maps to correct message`() {
        // Mutant killed: wrong message for NotConnected
        val content = ErrorContent.fromNotConnected()
        assertEquals(
            "VPN is not currently connected.",
            content.message
        )
    }

    @Test
    fun `NotConnected has no retry action`() {
        // Mutant killed: NotConnected incorrectly offers retry
        val content = ErrorContent.fromNotConnected()
        assertNull(content.retryLabel)
    }
}
