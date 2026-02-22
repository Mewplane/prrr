// FRD: specs/frds/FRD-M009-qr-code-scanner.md
package com.prrr.vpn.android.scanner

import android.util.Log
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage

private const val TAG = "QRCodeAnalyzer"
private const val DEBOUNCE_THRESHOLD_MS = 2000L

/**
 * ImageAnalyzer that uses ML Kit to detect QR codes in camera frames.
 * Implements debouncing to prevent scanning the same QR code multiple times.
 */
class QRCodeAnalyzer(
    private val onQRCodeDetected: (String) -> Unit
) : ImageAnalysis.Analyzer {

    private val scanner = BarcodeScanning.getClient()
    private var lastScannedValue: String? = null
    private var lastScannedTime: Long = 0

    @androidx.camera.core.ExperimentalGetImage
    override fun analyze(imageProxy: ImageProxy) {
        val mediaImage = imageProxy.image
        if (mediaImage == null) {
            imageProxy.close()
            return
        }

        val image = InputImage.fromMediaImage(
            mediaImage,
            imageProxy.imageInfo.rotationDegrees
        )

        scanner.process(image)
            .addOnSuccessListener { barcodes ->
                processBarcodes(barcodes)
            }
            .addOnFailureListener { exception ->
                Log.e(TAG, "Barcode scanning failed", exception)
            }
            .addOnCompleteListener {
                imageProxy.close()
            }
    }

    private fun processBarcodes(barcodes: List<Barcode>) {
        val qrCode = barcodes.firstOrNull { it.format == Barcode.FORMAT_QR_CODE }
            ?: return

        val rawValue = qrCode.rawValue ?: return

        // Debouncing: ignore if same QR code scanned recently
        val currentTime = System.currentTimeMillis()
        if (rawValue == lastScannedValue &&
            currentTime - lastScannedTime < DEBOUNCE_THRESHOLD_MS
        ) {
            return
        }

        lastScannedValue = rawValue
        lastScannedTime = currentTime

        onQRCodeDetected(rawValue)
    }
}
