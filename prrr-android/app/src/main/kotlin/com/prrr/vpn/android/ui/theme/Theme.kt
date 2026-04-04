package com.prrr.vpn.android.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val PrrrColorScheme = darkColorScheme(
    primary = PrrrWhite,
    onPrimary = PrrrBlack,
    secondary = PrrrTextDim,
    onSecondary = PrrrBlack,
    tertiary = PrrrSuccess,
    background = PrrrBlack,
    onBackground = PrrrWhite,
    surface = PrrrSurface,
    onSurface = PrrrWhite,
    surfaceVariant = PrrrSurface,
    onSurfaceVariant = PrrrTextDim,
    outline = PrrrBorder,
    error = PrrrDanger,
    onError = PrrrWhite,
    errorContainer = PrrrDanger.copy(alpha = 0.15f),
    onErrorContainer = PrrrDanger,
)

@Composable
fun PrrrVPNTheme(
    content: @Composable () -> Unit
) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = PrrrBlack.toArgb()
            window.navigationBarColor = PrrrBlack.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = false
            WindowCompat.getInsetsController(window, view).isAppearanceLightNavigationBars = false
        }
    }

    MaterialTheme(
        colorScheme = PrrrColorScheme,
        typography = Typography,
        content = content
    )
}
