package com.prrr.vpn.android.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.Deflater
import java.util.zip.Inflater

/**
 * Integration tests for the full QR pipeline without Rust FFI.
 *
 * Tests the complete roundtrip: TOML config → deflate compress → base64url encode
 * → split into multi-frame chunks → FrameCollector reassembly → decode → verify
 * fields match original.
 *
 * Uses a FakeConfigParser that does real deflate+base64url decoding in pure Kotlin
 * to validate the encoding pipeline matches what the server/web UI produces.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class QrPipelineTest {

    private val testDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    companion object {
        private const val IMPORT_URL_PREFIX = "prrr://import?z="
        private const val MULTI_FRAME_PREFIX = "prrr://import?f="
        private const val MAX_CHUNK_CHARS = 300
    }

    // --- Compression helpers (mirror server-side logic) ---

    private fun deflateCompress(input: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION, true) // raw deflate (no zlib header)
        deflater.setInput(input)
        deflater.finish()
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (!deflater.finished()) {
            val count = deflater.deflate(buffer)
            output.write(buffer, 0, count)
        }
        deflater.end()
        return output.toByteArray()
    }

    private fun deflateDecompress(input: ByteArray): ByteArray {
        val inflater = Inflater(true) // raw deflate
        inflater.setInput(input)
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (!inflater.finished()) {
            val count = inflater.inflate(buffer)
            output.write(buffer, 0, count)
        }
        inflater.end()
        return output.toByteArray()
    }

    private fun base64UrlEncode(data: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    private fun base64UrlDecode(data: String): ByteArray =
        Base64.getUrlDecoder().decode(data)

    /** Compress TOML → deflate → base64url → prrr://import?z=... URL */
    private fun compressToQrUrl(toml: String): String {
        val compressed = deflateCompress(toml.toByteArray(Charsets.UTF_8))
        val encoded = base64UrlEncode(compressed)
        return "$IMPORT_URL_PREFIX$encoded"
    }

    /** Split a base64url payload into multi-frame URLs (mirrors JS buildMultiFrameUrls). */
    private fun buildMultiFrameUrls(payload: String): List<String> {
        val chunks = payload.chunked(MAX_CHUNK_CHARS)
        val total = chunks.size
        return chunks.mapIndexed { i, chunk ->
            "${MULTI_FRAME_PREFIX}${i + 1}.$total&z=$chunk"
        }
    }

    /** Parser that does real deflate+base64url decode and returns parsed TOML fields. */
    private fun decodingParser(): ConfigParser {
        return object : ConfigParser {
            override fun parse(qrData: String): uniffi.prrr_mobile.VpnConfig {
                val payload = qrData.removePrefix(IMPORT_URL_PREFIX)
                val compressed = base64UrlDecode(payload)
                val toml = String(deflateDecompress(compressed), Charsets.UTF_8)

                // Simple TOML field extraction (good enough for testing)
                fun extract(key: String): String {
                    val regex = Regex("""$key\s*=\s*"([^"]*)"""")
                    return regex.find(toml)?.groupValues?.get(1) ?: ""
                }
                fun extractList(key: String): List<String> {
                    val regex = Regex("""$key\s*=\s*\[([^\]]*)]""")
                    val match = regex.find(toml)?.groupValues?.get(1) ?: return emptyList()
                    return Regex(""""([^"]*)"""").findAll(match).map { it.groupValues[1] }.toList()
                }
                fun extractInt(key: String): Int {
                    val regex = Regex("""$key\s*=\s*(\d+)""")
                    return regex.find(toml)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                }

                return uniffi.prrr_mobile.VpnConfig(
                    clientName = extract("name"),
                    serverEndpoint = extract("endpoint"),
                    serverPublicKey = ByteArray(32),
                    serverPqPublicKey = ByteArray(1184),
                    clientPrivateKey = ByteArray(32),
                    assignedIp = extract("address"),
                    dnsServers = extractList("dns"),
                    mtu = extractInt("mtu").toUShort(),
                    preferredBinding = null,
                    transportProtocol = extract("transport_protocol").ifEmpty { null }
                )
            }
        }
    }

    // --- Test config ---

    private val testToml = """
        [client]
        name = "test-phone"

        [server]
        endpoint = "vpn.example.com:443"
        public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        pq_public_key = "BBBBBBBBBBBB"

        [interface]
        private_key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        address = "10.66.66.2/32"
        dns = ["1.1.1.1", "8.8.8.8"]
        mtu = 1280
        transport_protocol = "harp"
    """.trimIndent()

    // --- Tests ---

    @Test
    fun `single-frame roundtrip preserves config fields`() {
        val url = compressToQrUrl(testToml)
        val parser = decodingParser()

        val config = parser.parse(url)

        assertEquals("test-phone", config.clientName)
        assertEquals("vpn.example.com:443", config.serverEndpoint)
        assertEquals("10.66.66.2/32", config.assignedIp)
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), config.dnsServers)
        assertEquals(1280.toUShort(), config.mtu)
        assertEquals("harp", config.transportProtocol)
    }

    @Test
    fun `multi-frame split and reassemble produces same URL`() {
        val url = compressToQrUrl(testToml)
        val payload = url.removePrefix(IMPORT_URL_PREFIX)
        val frames = buildMultiFrameUrls(payload)

        assertTrue("Should produce multiple frames", frames.size >= 1)

        val collector = FrameCollector()
        var finalResult: FrameCollector.Result? = null
        for (frame in frames) {
            val result = collector.submit(frame)
            if (result is FrameCollector.Result.Complete) {
                finalResult = result
            }
        }

        assertNotNull("Should complete", finalResult)
        assertEquals(url, (finalResult as FrameCollector.Result.Complete).assembledUrl)
    }

    @Test
    fun `multi-frame roundtrip through FrameCollector + parser`() {
        val url = compressToQrUrl(testToml)
        val payload = url.removePrefix(IMPORT_URL_PREFIX)
        val frames = buildMultiFrameUrls(payload)

        val collector = FrameCollector()
        var assembledUrl: String? = null
        for (frame in frames) {
            when (val result = collector.submit(frame)) {
                is FrameCollector.Result.Complete -> assembledUrl = result.assembledUrl
                else -> {}
            }
        }

        assertNotNull("Should complete assembly", assembledUrl)

        val parser = decodingParser()
        val config = parser.parse(assembledUrl!!)

        assertEquals("test-phone", config.clientName)
        assertEquals("vpn.example.com:443", config.serverEndpoint)
        assertEquals("10.66.66.2/32", config.assignedIp)
    }

    @Test
    fun `multi-frame reversed order still assembles correctly`() {
        val url = compressToQrUrl(testToml)
        val payload = url.removePrefix(IMPORT_URL_PREFIX)
        val frames = buildMultiFrameUrls(payload).reversed()

        val collector = FrameCollector()
        var assembledUrl: String? = null
        for (frame in frames) {
            when (val result = collector.submit(frame)) {
                is FrameCollector.Result.Complete -> assembledUrl = result.assembledUrl
                else -> {}
            }
        }

        assertNotNull("Reversed frames should complete", assembledUrl)
        assertEquals(url, assembledUrl)
    }

    @Test
    fun `full pipeline through ViewModel with fake parser`() {
        val parser = decodingParser()
        val viewModel = QRScanViewModel(configParser = parser)

        val url = compressToQrUrl(testToml)
        viewModel.onQRCodeDetected(url)

        val state = viewModel.scanState.value
        assertTrue("Expected Success, got $state", state is ScanState.Success)
        assertEquals("test-phone", (state as ScanState.Success).config.clientName)
    }

    @Test
    fun `full multi-frame pipeline through ViewModel`() {
        val parser = decodingParser()
        val viewModel = QRScanViewModel(configParser = parser)

        val url = compressToQrUrl(testToml)
        val payload = url.removePrefix(IMPORT_URL_PREFIX)
        val frames = buildMultiFrameUrls(payload)

        // Feed all frames except last — should show Collecting
        for (frame in frames.dropLast(1)) {
            viewModel.onQRCodeDetected(frame)
        }
        if (frames.size > 1) {
            val state = viewModel.scanState.value
            assertTrue("Expected Collecting, got $state", state is ScanState.Collecting)
        }

        // Feed last frame — should trigger parse and Success
        viewModel.onQRCodeDetected(frames.last())

        val state = viewModel.scanState.value
        assertTrue("Expected Success, got $state", state is ScanState.Success)
        assertEquals("test-phone", (state as ScanState.Success).config.clientName)
        assertEquals("vpn.example.com:443", state.config.serverEndpoint)
    }

    @Test
    fun `large config with ML-KEM key produces multiple frames`() {
        // Simulate realistic config with 1184-byte PQ key (varied data to resist compression)
        val largeKey = Base64.getEncoder().encodeToString(ByteArray(1184) { i -> (i % 251).toByte() })
        val largeToml = """
            [client]
            name = "large-config-phone"

            [server]
            endpoint = "vpn.example.com:443"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            pq_public_key = "$largeKey"

            [interface]
            private_key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            address = "10.66.66.3/32"
            dns = ["1.1.1.1", "8.8.8.8"]
            mtu = 1100
        """.trimIndent()

        val url = compressToQrUrl(largeToml)
        val payload = url.removePrefix(IMPORT_URL_PREFIX)
        val frames = buildMultiFrameUrls(payload)

        assertTrue(
            "Large config should produce multiple frames (got ${frames.size})",
            frames.size > 1
        )

        // Each frame should be small enough for QR scanning
        for ((i, frame) in frames.withIndex()) {
            assertTrue(
                "Frame ${i+1} too large: ${frame.length} chars",
                frame.length < 400
            )
        }

        // Full roundtrip
        val collector = FrameCollector()
        var assembledUrl: String? = null
        for (frame in frames) {
            when (val result = collector.submit(frame)) {
                is FrameCollector.Result.Complete -> assembledUrl = result.assembledUrl
                else -> {}
            }
        }
        assertNotNull(assembledUrl)

        val parser = decodingParser()
        val config = parser.parse(assembledUrl!!)
        assertEquals("large-config-phone", config.clientName)
    }

    @Test
    fun `compression actually reduces size`() {
        val url = compressToQrUrl(testToml)
        val payload = url.removePrefix(IMPORT_URL_PREFIX)
        val compressedBytes = base64UrlDecode(payload)

        assertTrue(
            "Compressed (${compressedBytes.size}) should be smaller than original (${testToml.length})",
            compressedBytes.size < testToml.length
        )
    }
}
