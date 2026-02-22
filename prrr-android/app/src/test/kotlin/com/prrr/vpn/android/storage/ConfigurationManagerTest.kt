// FRD: specs/frds/FRD-M010-configuration-storage.md
package com.prrr.vpn.android.storage

import android.content.Context
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import uniffi.prrr_mobile.VpnConfig

@RunWith(RobolectricTestRunner::class)
class ConfigurationManagerTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = RuntimeEnvironment.getApplication()
        // Clear any existing configuration before each test
        ConfigurationManager.deleteConfiguration(context)
    }

    @Test
    fun `hasConfiguration returns false when no config stored`() {
        assertFalse(ConfigurationManager.hasConfiguration(context))
    }

    @Test
    fun `loadConfiguration returns null when no config stored`() {
        val config = ConfigurationManager.loadConfiguration(context)
        assertNull(config)
    }

    @Test
    fun `saveConfiguration stores valid config`() {
        val config = createTestConfig()

        val result = ConfigurationManager.saveConfiguration(context, config)

        assertTrue(result is SaveResult.Success)
        assertTrue(ConfigurationManager.hasConfiguration(context))
    }

    @Test
    fun `loadConfiguration returns saved config`() {
        val originalConfig = createTestConfig()
        ConfigurationManager.saveConfiguration(context, originalConfig)

        val loadedConfig = ConfigurationManager.loadConfiguration(context)

        assertNotNull(loadedConfig)
        assertEquals(originalConfig.clientName, loadedConfig?.clientName)
        assertEquals(originalConfig.serverEndpoint, loadedConfig?.serverEndpoint)
        assertEquals(originalConfig.assignedIp, loadedConfig?.assignedIp)
        assertEquals(originalConfig.mtu, loadedConfig?.mtu)
    }

    @Test
    fun `deleteConfiguration removes stored config`() {
        val config = createTestConfig()
        ConfigurationManager.saveConfiguration(context, config)
        assertTrue(ConfigurationManager.hasConfiguration(context))

        val deleted = ConfigurationManager.deleteConfiguration(context)

        assertTrue(deleted)
        assertFalse(ConfigurationManager.hasConfiguration(context))
        assertNull(ConfigurationManager.loadConfiguration(context))
    }

    @Test
    fun `overwriteConfiguration replaces existing config`() {
        val config1 = createTestConfig("Client1")
        val config2 = createTestConfig("Client2")

        ConfigurationManager.saveConfiguration(context, config1)
        ConfigurationManager.saveConfiguration(context, config2)

        val loadedConfig = ConfigurationManager.loadConfiguration(context)

        assertEquals("Client2", loadedConfig?.clientName)
    }

    private fun createTestConfig(clientName: String = "Test Client"): VpnConfig {
        return VpnConfig(
            clientName = clientName,
            serverEndpoint = "vpn.example.com:443",
            serverPublicKey = ByteArray(32) { it.toByte() },
            serverPqPublicKey = ByteArray(1184) { it.toByte() },
            clientPrivateKey = ByteArray(32) { it.toByte() },
            assignedIp = "10.66.66.2/32",
            dnsServers = listOf("1.1.1.1", "8.8.8.8"),
            mtu = 1420u
        )
    }
}
