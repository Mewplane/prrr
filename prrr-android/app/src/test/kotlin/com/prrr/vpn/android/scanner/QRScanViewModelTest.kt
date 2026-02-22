// FRD: specs/frds/FRD-M009-qr-code-scanner.md
package com.prrr.vpn.android.scanner

import org.junit.Test
import org.junit.Assert.*

class QRScanViewModelTest {

    @Test
    fun `viewmodel starts in idle state`() {
        // Plan: Verify initial state is Idle
        // Test-RED: Create ViewModel and check initial state
        val viewModel = QRScanViewModel()

        assertEquals(ScanState.Idle, viewModel.scanState.value)
    }

    @Test
    fun `onQRCodeDetected with non-prrr URL shows error`() {
        // Plan: Validate that non-prrr:// URLs are rejected
        // Test-RED: Pass https:// URL and expect error state
        val viewModel = QRScanViewModel()

        viewModel.onQRCodeDetected("https://example.com")

        val state = viewModel.scanState.value
        assertTrue(state is ScanState.Error)
        assertTrue((state as ScanState.Error).message.contains("prrr"))
    }

    @Test
    fun `onQRCodeDetected with invalid config shows error`() {
        // Plan: Validate Rust parser rejection is handled
        // Test-RED: Pass prrr:// URL with invalid base64 and expect error
        val viewModel = QRScanViewModel()

        viewModel.onQRCodeDetected("prrr://import?config=invalid!!!")

        val state = viewModel.scanState.value
        assertTrue(state is ScanState.Error)
    }
}
