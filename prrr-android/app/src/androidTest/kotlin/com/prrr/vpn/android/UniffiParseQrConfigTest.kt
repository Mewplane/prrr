package com.prrr.vpn.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*
import uniffi.prrr_mobile.MobileException
import uniffi.prrr_mobile.parseQrConfig
import uniffi.prrr_mobile.validateConfig
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.Deflater

/**
 * Instrumented test that calls the real Rust UniFFI `parseQrConfig` function
 * via JNA on an Android device/emulator. This tests the actual FFI bridge,
 * not a fake — closing the gap between Kotlin unit tests (which use
 * FakeConfigParser) and production code.
 *
 * Requires: device/emulator with the prrr_mobile.aar native library loaded.
 *
 * Run with:
 *   ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class UniffiParseQrConfigTest {

    companion object {
        private const val IMPORT_URL_PREFIX = "prrr://import?z="
    }

    /** Deflate-compress and base64url-encode to prrr://import?z=... URL. */
    private fun compressToQrUrl(toml: String): String {
        val deflater = Deflater(Deflater.BEST_COMPRESSION, true)
        deflater.setInput(toml.toByteArray(Charsets.UTF_8))
        deflater.finish()
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (!deflater.finished()) {
            val count = deflater.deflate(buffer)
            output.write(buffer, 0, count)
        }
        deflater.end()
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(output.toByteArray())
        return "$IMPORT_URL_PREFIX$encoded"
    }

    /** Generate a valid test config TOML with realistic key sizes. */
    private fun testConfigToml(): String {
        val publicKey = Base64.getEncoder().encodeToString(ByteArray(32) { 0xAA.toByte() })
        val pqPublicKey = Base64.getEncoder().encodeToString(ByteArray(1184) { 0xBB.toByte() })
        val privateKey = Base64.getEncoder().encodeToString(ByteArray(32) { 0xCC.toByte() })

        return """
            [client]
            name = "uniffi-test-client"

            [server]
            endpoint = "vpn.example.com:443"
            server_name = "vpn.example.com"
            public_key = "$publicKey"
            pq_public_key = "$pqPublicKey"

            [interface]
            private_key = "$privateKey"
            address = "10.66.66.2/32"
            dns = ["1.1.1.1", "8.8.8.8"]
            mtu = 1100
            transport_protocol = "masque"
        """.trimIndent()
    }

    @Test
    fun parseQrConfig_with_valid_config_returns_correct_fields() {
        val toml = testConfigToml()
        val url = compressToQrUrl(toml)

        val config = parseQrConfig(url)

        assertEquals("uniffi-test-client", config.clientName)
        assertEquals("vpn.example.com:443", config.serverEndpoint)
        assertEquals("10.66.66.2/32", config.assignedIp)
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), config.dnsServers)
        assertEquals(1100.toUShort(), config.mtu)
        assertEquals("masque", config.transportProtocol)
        assertEquals(32, config.serverPublicKey.size)
        assertEquals(1184, config.serverPqPublicKey.size)
        assertEquals(32, config.clientPrivateKey.size)
    }

    @Test
    fun parseQrConfig_result_passes_validateConfig() {
        val toml = testConfigToml()
        val url = compressToQrUrl(toml)

        val config = parseQrConfig(url)
        // validateConfig throws on failure — if this doesn't throw, it passes
        validateConfig(config)
    }

    @Test(expected = MobileException.InvalidConfig::class)
    fun parseQrConfig_rejects_invalid_prefix() {
        parseQrConfig("https://example.com/not-a-prrr-url")
    }

    @Test(expected = MobileException.InvalidConfig::class)
    fun parseQrConfig_rejects_corrupt_data() {
        parseQrConfig("${IMPORT_URL_PREFIX}SGVsbG8gV29ybGQ")
    }

    @Test
    fun parseQrConfig_ignores_unknown_fields() {
        // server_name is in [server] but not in the mobile parser's TomlServer struct.
        // serde should silently ignore it.
        val toml = testConfigToml()
        assertTrue("test config must contain server_name", toml.contains("server_name"))
        val url = compressToQrUrl(toml)

        // Should parse without error despite unknown field
        val config = parseQrConfig(url)
        assertEquals("uniffi-test-client", config.clientName)
    }
}
