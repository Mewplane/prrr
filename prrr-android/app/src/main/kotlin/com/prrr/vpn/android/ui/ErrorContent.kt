// FRD: specs/frds/FRD-M013-settings-battery-errors.md
package com.prrr.vpn.android.ui

/**
 * User-facing error content mapped from MobileError variants.
 * Each factory method corresponds to a specific error type and provides
 * a human-readable title, message, and optional retry label.
 */
data class ErrorContent(
    val title: String,
    val message: String,
    val retryLabel: String?
) {
    companion object {
        private const val TITLE_INVALID_CONFIG = "Invalid Configuration"
        private const val MSG_INVALID_CONFIG =
            "The QR code or configuration is invalid. Please scan a valid prrr VPN QR code."

        private const val TITLE_CONNECTION_FAILED = "Connection Failed"
        private const val MSG_CONNECTION_FAILED =
            "Unable to reach the VPN server. Check your internet connection and try again."

        private const val TITLE_HANDSHAKE_FAILED = "Security Check Failed"
        private const val MSG_HANDSHAKE_FAILED =
            "The server's security credentials could not be verified. Your access may have been revoked."

        private const val TITLE_NETWORK_ERROR = "Network Error"
        private const val MSG_NETWORK_ERROR =
            "A network error occurred. Please check your connection and try again."

        private const val TITLE_NOT_CONNECTED = "Not Connected"
        private const val MSG_NOT_CONNECTED =
            "VPN is not currently connected."

        private const val LABEL_RETRY = "Retry"

        fun fromInvalidConfig(): ErrorContent = ErrorContent(
            title = TITLE_INVALID_CONFIG,
            message = MSG_INVALID_CONFIG,
            retryLabel = null
        )

        fun fromConnectionFailed(): ErrorContent = ErrorContent(
            title = TITLE_CONNECTION_FAILED,
            message = MSG_CONNECTION_FAILED,
            retryLabel = LABEL_RETRY
        )

        fun fromHandshakeFailed(): ErrorContent = ErrorContent(
            title = TITLE_HANDSHAKE_FAILED,
            message = MSG_HANDSHAKE_FAILED,
            retryLabel = null
        )

        fun fromNetworkError(): ErrorContent = ErrorContent(
            title = TITLE_NETWORK_ERROR,
            message = MSG_NETWORK_ERROR,
            retryLabel = LABEL_RETRY
        )

        fun fromNotConnected(): ErrorContent = ErrorContent(
            title = TITLE_NOT_CONNECTED,
            message = MSG_NOT_CONNECTED,
            retryLabel = null
        )
    }
}
