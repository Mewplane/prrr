package com.prrr.vpn.android.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.prrr.vpn.android.R
import com.prrr.vpn.android.viewmodel.ConnectionStatus

private val catFrames = listOf(
    R.drawable.cat_frame_0, // Key held — connected
    R.drawable.cat_frame_1,
    R.drawable.cat_frame_2,
    R.drawable.cat_frame_3,
    R.drawable.cat_frame_4, // Key dropped — disconnected
)

/**
 * Animated cat status icon.
 * Frame 0 (key held) = connected, frame 4 (key on ground) = disconnected.
 * Animates through intermediate frames on state transitions.
 */
@Composable
fun StatusIcon(status: ConnectionStatus) {
    val targetFrame = when (status) {
        ConnectionStatus.CONNECTED -> 0
        ConnectionStatus.CONNECTING -> 2
        ConnectionStatus.DISCONNECTED -> 4
        ConnectionStatus.ERROR -> 4
    }

    val animatedFrame by animateIntAsState(
        targetValue = targetFrame,
        animationSpec = tween(
            durationMillis = 400,
            easing = LinearEasing
        ),
        label = "catFrame"
    )

    val frameIndex = animatedFrame.coerceIn(0, catFrames.lastIndex)
    val description = when (status) {
        ConnectionStatus.CONNECTED -> "Connected"
        ConnectionStatus.CONNECTING -> "Connecting"
        ConnectionStatus.DISCONNECTED -> "Disconnected"
        ConnectionStatus.ERROR -> "Error"
    }

    Image(
        painter = painterResource(id = catFrames[frameIndex]),
        contentDescription = null,
        modifier = Modifier
            .size(180.dp)
            .semantics { contentDescription = description }
    )
}
