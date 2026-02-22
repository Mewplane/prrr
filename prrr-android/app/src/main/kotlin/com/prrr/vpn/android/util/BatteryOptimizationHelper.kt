// FRD: specs/frds/FRD-M013-settings-battery-errors.md
package com.prrr.vpn.android.util

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings

/**
 * Utility for detecting and managing Android battery optimization status.
 * VPN services need battery optimization exemption to maintain stable connections.
 */
object BatteryOptimizationHelper {

    /**
     * Check if the app is currently exempt from battery optimization.
     * Returns true if the app is allowed to run unrestricted (ignoring Doze/App Standby).
     */
    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            ?: return false
        return powerManager.isIgnoringBatteryOptimizations(context.packageName)
    }

    /**
     * Create an intent to request battery optimization exemption from the system.
     * Launches the system dialog asking the user to exempt this app.
     */
    fun createBatteryOptimizationIntent(context: Context): Intent {
        return Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:${context.packageName}")
        }
    }
}
