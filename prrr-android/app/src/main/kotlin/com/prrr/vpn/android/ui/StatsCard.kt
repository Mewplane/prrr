package com.prrr.vpn.android.ui

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.prrr.vpn.android.ui.theme.PrrrBorder
import com.prrr.vpn.android.ui.theme.PrrrSurface
import com.prrr.vpn.android.ui.theme.PrrrTextDim
import com.prrr.vpn.android.ui.theme.PrrrWhite
import uniffi.prrr_mobile.ConnectionStats

@Composable
fun StatsCard(stats: ConnectionStats) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp)
            .border(1.dp, PrrrBorder, RoundedCornerShape(8.dp)),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = PrrrSurface)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            StatRow("Transport", stats.activeTransport.uppercase())
            StatRow("Duration", formatDuration(stats.durationSecs))
            StatRow("Sent", formatBytes(stats.bytesSent))
            StatRow("Received", formatBytes(stats.bytesReceived))
            if (stats.serverLatencyMs > 0u) {
                StatRow("Latency", "${stats.serverLatencyMs}ms")
            }
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            fontSize = 14.sp,
            color = PrrrTextDim
        )
        Text(
            text = value,
            fontSize = 14.sp,
            color = PrrrWhite
        )
    }
}

private fun formatDuration(seconds: ULong): String {
    val hours = seconds / 3600u
    val minutes = (seconds % 3600u) / 60u
    return "${hours}h ${minutes}m"
}

private fun formatBytes(bytes: ULong): String {
    return when {
        bytes < 1024u -> "$bytes B"
        bytes < 1024u * 1024u -> "${bytes / 1024u} KB"
        bytes < 1024u * 1024u * 1024u -> "${bytes / (1024u * 1024u)} MB"
        else -> {
            val gb = bytes.toDouble() / (1024.0 * 1024.0 * 1024.0)
            "%.1f GB".format(gb)
        }
    }
}
