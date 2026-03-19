// FRD: specs/frds/FRD-M009-qr-code-scanner.md
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
import uniffi.prrr_mobile.MobileException
import uniffi.prrr_mobile.VpnConfig

/** Fake parser that returns a predetermined config or throws. */
class FakeConfigParser(
    private val result: (String) -> VpnConfig = { _ -> fakeVpnConfig() }
) : ConfigParser {
    var lastParsedUrl: String? = null
        private set
    var parseCount: Int = 0
        private set

    override fun parse(qrData: String): VpnConfig {
        lastParsedUrl = qrData
        parseCount++
        return result(qrData)
    }
}

/** Fake parser that always throws InvalidConfig. */
class FailingConfigParser(private val reason: String = "invalid config") : ConfigParser {
    override fun parse(qrData: String): VpnConfig {
        throw MobileException.InvalidConfig(reason)
    }
}

fun fakeVpnConfig(
    clientName: String = "test-client",
    serverEndpoint: String = "vpn.example.com:443"
) = VpnConfig(
    clientName = clientName,
    serverEndpoint = serverEndpoint,
    serverPublicKey = ByteArray(32),
    serverPqPublicKey = ByteArray(1184),
    clientPrivateKey = ByteArray(32),
    assignedIp = "10.66.66.2/32",
    dnsServers = listOf("1.1.1.1"),
    mtu = 1100u.toUShort(),
    preferredBinding = null,
    transportProtocol = null
)

@OptIn(ExperimentalCoroutinesApi::class)
class QRScanViewModelTest {

    private val testDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    // --- Basic state tests ---

    @Test
    fun `viewmodel starts in idle state`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())
        assertEquals(ScanState.Idle, viewModel.scanState.value)
    }

    @Test
    fun `non-prrr URL is silently ignored`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())
        viewModel.onQRCodeDetected("https://example.com")
        assertEquals(ScanState.Idle, viewModel.scanState.value)
    }

    // --- Single-frame tests (with fake parser) ---

    @Test
    fun `single-frame success returns parsed config`() {
        val parser = FakeConfigParser { fakeVpnConfig(clientName = "my-phone") }
        val viewModel = QRScanViewModel(configParser = parser)

        viewModel.onQRCodeDetected("prrr://import?z=dGVzdA")

        val state = viewModel.scanState.value
        assertTrue("Expected Success, got $state", state is ScanState.Success)
        assertEquals("my-phone", (state as ScanState.Success).config.clientName)
        assertEquals("prrr://import?z=dGVzdA", parser.lastParsedUrl)
    }

    @Test
    fun `single-frame parse error shows error state`() {
        val viewModel = QRScanViewModel(configParser = FailingConfigParser("bad data"))

        viewModel.onQRCodeDetected("prrr://import?z=dGVzdA")

        val state = viewModel.scanState.value
        assertTrue("Expected Error, got $state", state is ScanState.Error)
        assertEquals("bad data", (state as ScanState.Error).message)
    }

    // --- Multi-frame tests ---

    @Test
    fun `multiframe first frame transitions to Collecting state`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")

        val state = viewModel.scanState.value
        assertTrue("Expected Collecting, got $state", state is ScanState.Collecting)
        assertEquals(1, (state as ScanState.Collecting).received)
        assertEquals(3, state.total)
    }

    @Test
    fun `multiframe collecting increments received count`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")
        viewModel.onQRCodeDetected("prrr://import?f=2.3&z=BBBB")

        val state = viewModel.scanState.value
        assertTrue("Expected Collecting, got $state", state is ScanState.Collecting)
        assertEquals(2, (state as ScanState.Collecting).received)
        assertEquals(3, state.total)
    }

    @Test
    fun `multiframe duplicate frame does not increment count`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")
        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")

        val state = viewModel.scanState.value
        assertTrue(state is ScanState.Collecting)
        assertEquals(1, (state as ScanState.Collecting).received)
    }

    @Test
    fun `multiframe out of order frames are collected`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=3.3&z=CCCC")
        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")

        val state = viewModel.scanState.value
        assertTrue(state is ScanState.Collecting)
        assertEquals(2, (state as ScanState.Collecting).received)
    }

    @Test
    fun `multiframe complete triggers parse with assembled URL`() {
        val parser = FakeConfigParser()
        val viewModel = QRScanViewModel(configParser = parser)

        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")
        viewModel.onQRCodeDetected("prrr://import?f=2.3&z=BBBB")
        viewModel.onQRCodeDetected("prrr://import?f=3.3&z=CCCC")

        val state = viewModel.scanState.value
        assertTrue("Expected Success, got $state", state is ScanState.Success)
        assertEquals("prrr://import?z=AAAABBBBCCCC", parser.lastParsedUrl)
    }

    @Test
    fun `multiframe invalid format shows error`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=bad&z=data")

        val state = viewModel.scanState.value
        assertTrue("Expected Error, got $state", state is ScanState.Error)
    }

    @Test
    fun `multiframe invalid index range shows error`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=0.3&z=data")

        val state = viewModel.scanState.value
        assertTrue("Expected Error, got $state", state is ScanState.Error)
    }

    @Test
    fun `multiframe index exceeding total shows error`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=4.3&z=data")

        val state = viewModel.scanState.value
        assertTrue("Expected Error, got $state", state is ScanState.Error)
    }

    @Test
    fun `multiframe total change resets collection`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")
        viewModel.onQRCodeDetected("prrr://import?f=2.3&z=BBBB")
        viewModel.onQRCodeDetected("prrr://import?f=1.5&z=XXXX")

        val state = viewModel.scanState.value
        assertTrue(state is ScanState.Collecting)
        assertEquals(1, (state as ScanState.Collecting).received)
        assertEquals(5, state.total)
    }

    @Test
    fun `resetState clears to idle`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")
        viewModel.resetState()

        assertEquals(ScanState.Idle, viewModel.scanState.value)
    }

    @Test
    fun `resetState after partial collection clears chunks`() {
        val viewModel = QRScanViewModel(configParser = FakeConfigParser())

        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")
        viewModel.onQRCodeDetected("prrr://import?f=2.3&z=BBBB")
        viewModel.resetState()

        viewModel.onQRCodeDetected("prrr://import?f=1.3&z=AAAA")

        val state = viewModel.scanState.value
        assertTrue(state is ScanState.Collecting)
        assertEquals(1, (state as ScanState.Collecting).received)
    }
}
