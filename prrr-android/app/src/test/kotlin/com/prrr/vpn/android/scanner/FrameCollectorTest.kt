package com.prrr.vpn.android.scanner

import org.junit.Test
import org.junit.Assert.*

class FrameCollectorTest {

    @Test
    fun `non-prrr URL returns null`() {
        val collector = FrameCollector()
        assertNull(collector.submit("https://example.com"))
    }

    @Test
    fun `single-frame URL returns SingleFrame`() {
        val collector = FrameCollector()
        val result = collector.submit("prrr://import?z=dGVzdA")
        assertTrue(result is FrameCollector.Result.SingleFrame)
        assertEquals("prrr://import?z=dGVzdA", (result as FrameCollector.Result.SingleFrame).url)
    }

    @Test
    fun `single-frame URL with whitespace is trimmed`() {
        val collector = FrameCollector()
        val result = collector.submit("  prrr://import?z=dGVzdA  ")
        assertTrue(result is FrameCollector.Result.SingleFrame)
    }

    @Test
    fun `first multi-frame returns NeedMore`() {
        val collector = FrameCollector()
        val result = collector.submit("prrr://import?f=1.3&z=AAAA")
        assertTrue(result is FrameCollector.Result.NeedMore)
        val needMore = result as FrameCollector.Result.NeedMore
        assertEquals(1, needMore.received)
        assertEquals(3, needMore.total)
    }

    @Test
    fun `collecting increments received count`() {
        val collector = FrameCollector()
        collector.submit("prrr://import?f=1.3&z=AAAA")
        val result = collector.submit("prrr://import?f=2.3&z=BBBB")
        assertTrue(result is FrameCollector.Result.NeedMore)
        assertEquals(2, (result as FrameCollector.Result.NeedMore).received)
    }

    @Test
    fun `duplicate frame does not increment count`() {
        val collector = FrameCollector()
        collector.submit("prrr://import?f=1.3&z=AAAA")
        val result = collector.submit("prrr://import?f=1.3&z=AAAA")
        assertTrue(result is FrameCollector.Result.NeedMore)
        assertEquals(1, (result as FrameCollector.Result.NeedMore).received)
    }

    @Test
    fun `out of order frames are collected`() {
        val collector = FrameCollector()
        collector.submit("prrr://import?f=3.3&z=CCCC")
        val result = collector.submit("prrr://import?f=1.3&z=AAAA")
        assertTrue(result is FrameCollector.Result.NeedMore)
        assertEquals(2, (result as FrameCollector.Result.NeedMore).received)
    }

    @Test
    fun `all frames received returns Complete with correct assembly`() {
        val collector = FrameCollector()
        collector.submit("prrr://import?f=1.3&z=AAAA")
        collector.submit("prrr://import?f=2.3&z=BBBB")
        val result = collector.submit("prrr://import?f=3.3&z=CCCC")

        assertTrue(result is FrameCollector.Result.Complete)
        assertEquals(
            "prrr://import?z=AAAABBBBCCCC",
            (result as FrameCollector.Result.Complete).assembledUrl
        )
    }

    @Test
    fun `out of order assembly preserves chunk order`() {
        val collector = FrameCollector()
        collector.submit("prrr://import?f=3.3&z=CCCC")
        collector.submit("prrr://import?f=1.3&z=AAAA")
        val result = collector.submit("prrr://import?f=2.3&z=BBBB")

        assertTrue(result is FrameCollector.Result.Complete)
        assertEquals(
            "prrr://import?z=AAAABBBBCCCC",
            (result as FrameCollector.Result.Complete).assembledUrl
        )
    }

    @Test
    fun `invalid format returns Error`() {
        val collector = FrameCollector()
        val result = collector.submit("prrr://import?f=bad&z=data")
        assertTrue(result is FrameCollector.Result.Error)
    }

    @Test
    fun `index zero returns Error`() {
        val collector = FrameCollector()
        val result = collector.submit("prrr://import?f=0.3&z=data")
        assertTrue(result is FrameCollector.Result.Error)
    }

    @Test
    fun `index exceeding total returns Error`() {
        val collector = FrameCollector()
        val result = collector.submit("prrr://import?f=4.3&z=data")
        assertTrue(result is FrameCollector.Result.Error)
    }

    @Test
    fun `total change resets collection`() {
        val collector = FrameCollector()
        collector.submit("prrr://import?f=1.3&z=AAAA")
        collector.submit("prrr://import?f=2.3&z=BBBB")

        // New session with different total
        val result = collector.submit("prrr://import?f=1.5&z=XXXX")
        assertTrue(result is FrameCollector.Result.NeedMore)
        assertEquals(1, (result as FrameCollector.Result.NeedMore).received)
        assertEquals(5, result.total)
    }

    @Test
    fun `reset clears state`() {
        val collector = FrameCollector()
        collector.submit("prrr://import?f=1.3&z=AAAA")
        collector.submit("prrr://import?f=2.3&z=BBBB")
        collector.reset()

        // After reset, starts fresh
        val result = collector.submit("prrr://import?f=1.3&z=XXXX")
        assertTrue(result is FrameCollector.Result.NeedMore)
        assertEquals(1, (result as FrameCollector.Result.NeedMore).received)
    }

    @Test
    fun `two-frame complete`() {
        val collector = FrameCollector()
        collector.submit("prrr://import?f=1.2&z=FIRST")
        val result = collector.submit("prrr://import?f=2.2&z=SECOND")

        assertTrue(result is FrameCollector.Result.Complete)
        assertEquals(
            "prrr://import?z=FIRSTSECOND",
            (result as FrameCollector.Result.Complete).assembledUrl
        )
    }

    @Test
    fun `unrecognized prrr URL returns Error`() {
        val collector = FrameCollector()
        val result = collector.submit("prrr://import?config=old_format")
        assertTrue(result is FrameCollector.Result.Error)
    }
}
