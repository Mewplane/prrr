// FRD: specs/frds/FRD-M012-main-ui-compose.md
package com.prrr.vpn.android.viewmodel

/**
 * VPN connection status for UI display.
 * Maps from Rust uniffi ConnectionStatus to Android-friendly enum.
 */
enum class ConnectionStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
}
