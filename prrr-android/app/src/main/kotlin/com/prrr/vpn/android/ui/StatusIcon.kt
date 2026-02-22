// FRD: specs/frds/FRD-M012-main-ui-compose.md
package com.prrr.vpn.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.prrr.vpn.android.viewmodel.ConnectionStatus

/**
 * Status icon showing current VPN connection state.
 * Color-coded circle with appropriate icon.
 */
@Composable
fun StatusIcon(status: ConnectionStatus) {
    val (color, icon, description) = getStatusVisuals(status)

    Box(
        modifier = Modifier
            .size(120.dp)
            .background(color, CircleShape)
            .semantics { contentDescription = description },
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(60.dp),
            tint = Color.White
        )
    }
}

private fun getStatusVisuals(status: ConnectionStatus): Triple<Color, ImageVector, String> {
    return when (status) {
        ConnectionStatus.DISCONNECTED -> Triple(
            Color(0xFF9E9E9E), // Gray
            Icons.Default.Close,
            "Disconnected"
        )
        ConnectionStatus.CONNECTING -> Triple(
            Color(0xFFFF9800), // Orange
            Icons.Default.Refresh,
            "Connecting"
        )
        ConnectionStatus.CONNECTED -> Triple(
            Color(0xFF4CAF50), // Green
            Icons.Default.CheckCircle,
            "Connected"
        )
        ConnectionStatus.ERROR -> Triple(
            Color(0xFFF44336), // Red
            Icons.Default.Warning,
            "Error"
        )
    }
}
