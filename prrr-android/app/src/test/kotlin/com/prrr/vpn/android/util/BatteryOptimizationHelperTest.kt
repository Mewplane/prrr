// FRD: specs/frds/FRD-M013-settings-battery-errors.md
package com.prrr.vpn.android.util

import android.content.Context
import android.provider.Settings
import org.junit.Before
import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Tests for BatteryOptimizationHelper.
 * Verifies intent creation for battery optimization exemption requests.
 *
 * Note: isIgnoringBatteryOptimizations() cannot be unit-tested because
 * Robolectric does not shadow PowerManager.isIgnoringBatteryOptimizations().
 * That method is verified via manual testing on device.
 *
 * Contract: Helper must produce correct system settings intent.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class BatteryOptimizationHelperTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = RuntimeEnvironment.getApplication()
    }

    @Test
    fun `createBatteryOptimizationIntent has correct action`() {
        // Mutant killed: wrong intent action
        val intent = BatteryOptimizationHelper.createBatteryOptimizationIntent(context)
        assertEquals(
            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
            intent.action
        )
    }

    @Test
    fun `createBatteryOptimizationIntent has correct data uri`() {
        // Mutant killed: wrong package in data URI
        val intent = BatteryOptimizationHelper.createBatteryOptimizationIntent(context)
        assertNotNull(intent.data)
        assertEquals("package:${context.packageName}", intent.data.toString())
    }

    @Test
    fun `createBatteryOptimizationIntent data uri contains package scheme`() {
        // Mutant killed: data URI uses wrong scheme (e.g., "content:" instead of "package:")
        val intent = BatteryOptimizationHelper.createBatteryOptimizationIntent(context)
        assertNotNull(intent.data)
        assertEquals("package", intent.data?.scheme)
    }

    @Test
    fun `createBatteryOptimizationIntent data uri contains correct package name`() {
        // Mutant killed: data URI has wrong package name
        val intent = BatteryOptimizationHelper.createBatteryOptimizationIntent(context)
        assertNotNull(intent.data)
        assertEquals(context.packageName, intent.data?.schemeSpecificPart)
    }
}
