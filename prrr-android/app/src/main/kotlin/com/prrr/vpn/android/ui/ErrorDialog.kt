// FRD: specs/frds/FRD-M013-settings-battery-errors.md
package com.prrr.vpn.android.ui

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import uniffi.prrr_mobile.MobileException

/**
 * Error dialog that maps MobileException variants to user-friendly messages.
 * Shows title, descriptive message, dismiss button, and optional retry action.
 */
@Composable
fun ErrorDialog(
    error: MobileException,
    onDismiss: () -> Unit,
    onRetry: (() -> Unit)? = null
) {
    val content = mapErrorToContent(error)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(content.title) },
        text = { Text(content.message) },
        confirmButton = {
            if (content.retryLabel != null && onRetry != null) {
                TextButton(onClick = {
                    onRetry()
                    onDismiss()
                }) {
                    Text(content.retryLabel)
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("OK")
            }
        }
    )
}

/**
 * Map a MobileException to user-facing ErrorContent.
 */
fun mapErrorToContent(error: MobileException): ErrorContent {
    return when (error) {
        is MobileException.InvalidConfig -> ErrorContent.fromInvalidConfig()
        is MobileException.ConnectionFailed -> ErrorContent.fromConnectionFailed()
        is MobileException.HandshakeFailed -> ErrorContent.fromHandshakeFailed()
        is MobileException.NetworkException -> ErrorContent.fromNetworkError()
        is MobileException.TunnelFailed -> ErrorContent.fromTunnelFailed()
        is MobileException.NotConnected -> ErrorContent.fromNotConnected()
    }
}
