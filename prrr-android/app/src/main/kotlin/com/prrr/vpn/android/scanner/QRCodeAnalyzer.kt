// FRD: specs/frds/FRD-M009-qr-code-scanner.md
package com.prrr.vpn.android.scanner

import android.util.Log
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer

private const val TAG = "QRCodeAnalyzer"
private const val DEBOUNCE_THRESHOLD_MS = 150L

/**
 * ImageAnalyzer that uses ZXing to detect QR codes in camera frames.
 *
 * Uses ZXing (pure Java) instead of ML Kit because ML Kit's Task callbacks
 * never fire on emulators without Google Play Services.
 */
class QRCodeAnalyzer(
    private val onQRCodeDetected: (String) -> Unit
) : ImageAnalysis.Analyzer {

    private val reader = MultiFormatReader().apply {
        setHints(mapOf(
            DecodeHintType.POSSIBLE_FORMATS to listOf(com.google.zxing.BarcodeFormat.QR_CODE),
            DecodeHintType.TRY_HARDER to true,
            DecodeHintType.CHARACTER_SET to "UTF-8"
        ))
    }
    private var lastScannedValue: String? = null
    private var lastScannedTime: Long = 0
    private var frameCount: Long = 0

    @androidx.camera.core.ExperimentalGetImage
    override fun analyze(imageProxy: ImageProxy) {
        frameCount++
        if (frameCount % 60 == 0L) {
            Log.d(TAG, "Analyzed $frameCount frames so far (${imageProxy.width}x${imageProxy.height})")
        }

        try {
            // Try downsampled first (better for screen moiré), fallback to raw crop
            val rawValue = decodeQrDownsampled(imageProxy)
                ?: decodeQrCropped(imageProxy)
            if (rawValue != null) {
                processDetection(rawValue)
            }
        } catch (e: Exception) {
            // ZXing throws NotFoundException when no QR is found — this is normal
        } finally {
            reader.reset()
            imageProxy.close()
        }
    }

    /** Downsample 2x with averaging — smooths screen moiré. */
    private fun decodeQrDownsampled(imageProxy: ImageProxy): String? {
        val plane = imageProxy.planes.firstOrNull() ?: return null
        val buffer = plane.buffer
        val data = ByteArray(buffer.remaining())
        buffer.get(data)

        val width = imageProxy.width
        val height = imageProxy.height
        val rowStride = plane.rowStride

        if (frameCount == 1L) {
            Log.i(TAG, "First frame: ${width}x${height}, rowStride=$rowStride, " +
                "dataSize=${data.size}, planes=${imageProxy.planes.size}, " +
                "format=${imageProxy.format}")
        }

        // Crop center 60% then downsample 2x — improves ZXing detection on
        // high-res sensors scanning QR codes from screens.
        val cropFraction = 0.6
        val cropW = (width * cropFraction).toInt()
        val cropH = (height * cropFraction).toInt()
        val cropLeft = (width - cropW) / 2
        val cropTop = (height - cropH) / 2

        // Downsample by averaging 2x2 blocks — reduces noise from screen moiré
        val dsW = cropW / 2
        val dsH = cropH / 2
        val downsampled = ByteArray(dsW * dsH)
        for (dy in 0 until dsH) {
            val sy = cropTop + dy * 2
            for (dx in 0 until dsW) {
                val sx = cropLeft + dx * 2
                val p00 = data[sy * rowStride + sx].toInt() and 0xFF
                val p01 = data[sy * rowStride + sx + 1].toInt() and 0xFF
                val p10 = data[(sy + 1) * rowStride + sx].toInt() and 0xFF
                val p11 = data[(sy + 1) * rowStride + sx + 1].toInt() and 0xFF
                downsampled[dy * dsW + dx] = ((p00 + p01 + p10 + p11) / 4).toByte()
            }
        }

        val source = PlanarYUVLuminanceSource(
            downsampled, dsW, dsH,
            0, 0, dsW, dsH,
            false
        )
        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
        val result = reader.decodeWithState(binaryBitmap)
        return result.text
    }

    /** Try raw center crop without downsampling. */
    private fun decodeQrCropped(imageProxy: ImageProxy): String? {
        val plane = imageProxy.planes.firstOrNull() ?: return null
        val buffer = plane.buffer
        buffer.rewind()
        val data = ByteArray(buffer.remaining())
        buffer.get(data)

        val width = imageProxy.width
        val height = imageProxy.height
        val rowStride = plane.rowStride

        val cropW = (width * 0.5).toInt()
        val cropH = (height * 0.5).toInt()
        val cropLeft = (width - cropW) / 2
        val cropTop = (height - cropH) / 2

        val source = PlanarYUVLuminanceSource(
            data, rowStride, height,
            cropLeft, cropTop, cropW, cropH,
            false
        )
        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
        reader.reset()
        val result = reader.decodeWithState(binaryBitmap)
        return result.text
    }

    private fun processDetection(rawValue: String) {
        Log.i(TAG, "QR detected: ${rawValue.take(80)}... (${rawValue.length} chars)")

        // Debouncing: ignore exact same value within threshold.
        // Short threshold to support multi-frame animated QR cycling.
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
