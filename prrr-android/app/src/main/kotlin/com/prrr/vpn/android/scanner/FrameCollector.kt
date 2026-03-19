package com.prrr.vpn.android.scanner

/**
 * Stateful collector for multi-frame QR chunks.
 *
 * Pure logic — no Android, ViewModel, or coroutine dependencies.
 * Handles the `prrr://import?f=<index>.<total>&z=<chunk>` protocol.
 */
class FrameCollector {

    sealed class Result {
        /** Single-frame URL detected — pass directly to parser. */
        data class SingleFrame(val url: String) : Result()
        /** Multi-frame chunk received, more needed. */
        data class NeedMore(val received: Int, val total: Int) : Result()
        /** All chunks received — assembled into single-frame URL. */
        data class Complete(val assembledUrl: String) : Result()
        /** Format error in the QR data. */
        data class Error(val message: String) : Result()
    }

    private val chunks = mutableMapOf<Int, String>()
    private var expectedTotal = 0

    companion object {
        private const val PRRR_URL_PREFIX = "prrr://import?"
        private const val SINGLE_FRAME_PREFIX = "prrr://import?z="
        private const val MULTI_FRAME_PREFIX = "prrr://import?f="
    }

    /**
     * Submit a raw QR code value. Returns the appropriate result.
     * Non-prrr URLs return null (silently ignored by the scanner).
     */
    fun submit(rawValue: String): Result? {
        val value = rawValue.trim()

        if (!value.startsWith(PRRR_URL_PREFIX)) {
            return null // not a prrr QR code
        }

        if (value.startsWith(SINGLE_FRAME_PREFIX)) {
            return Result.SingleFrame(value)
        }

        if (value.startsWith(MULTI_FRAME_PREFIX)) {
            return processMultiFrame(value)
        }

        return Result.Error("Unrecognized prrr URL format")
    }

    private fun processMultiFrame(rawValue: String): Result {
        val params = rawValue.removePrefix(PRRR_URL_PREFIX)
        val fParam = params.substringBefore("&z=").removePrefix("f=")
        val chunkData = params.substringAfter("&z=", "")

        val parts = fParam.split(".")
        if (parts.size != 2) {
            return Result.Error("Invalid multi-frame QR format")
        }

        val index = parts[0].toIntOrNull()
            ?: return Result.Error("Invalid frame index: ${parts[0]}")
        val total = parts[1].toIntOrNull()
            ?: return Result.Error("Invalid frame total: ${parts[1]}")

        if (index < 1 || index > total || total < 1) {
            return Result.Error("Invalid frame index: $index/$total")
        }

        // Reset if total changed (new QR session)
        if (expectedTotal != total) {
            chunks.clear()
            expectedTotal = total
        }

        if (!chunks.containsKey(index)) {
            chunks[index] = chunkData
        }

        // All chunks received — reassemble
        if (chunks.size == total) {
            val fullData = (1..total).joinToString("") { i -> chunks[i] ?: "" }
            val assembledUrl = SINGLE_FRAME_PREFIX + fullData
            return Result.Complete(assembledUrl)
        }

        return Result.NeedMore(received = chunks.size, total = total)
    }

    fun reset() {
        chunks.clear()
        expectedTotal = 0
    }
}
