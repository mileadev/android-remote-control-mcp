package com.danielealbano.androidremotecontrolmcp.integration

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * Unit test for [retryUntil], the bounded poll behind the Cloudflare tunnel test's
 * DNS-readiness wait.
 *
 * Pure timing logic only: the conditions are in-process counters, so this needs no
 * network and no `cloudflared`.
 */
@DisplayName("RetryUntilTest")
class RetryUntilTest {
    @Test
    fun `returns true as soon as the condition holds`() {
        val probes = AtomicInteger()

        val startedAt = System.nanoTime()
        val ready = retryUntil(timeoutMs = 5_000, intervalMs = 20) { probes.incrementAndGet() >= 3 }
        val elapsedMs = (System.nanoTime() - startedAt) / NANOS_PER_MILLI

        assertTrue(ready)
        assertEquals(3, probes.get(), "the poll must stop probing once the condition holds")
        assertTrue(elapsedMs < 1_000) { "expected an early exit, took ${elapsedMs}ms" }
    }

    @Test
    fun `probes immediately instead of waiting one interval first`() {
        val probes = AtomicInteger()

        val ready = retryUntil(timeoutMs = 5_000, intervalMs = 1_000) { probes.incrementAndGet() > 0 }

        assertTrue(ready)
        assertEquals(1, probes.get())
    }

    @Test
    fun `gives up at the deadline when the condition never holds`() {
        val probes = AtomicInteger()
        val timeoutMs = 300L

        val startedAt = System.nanoTime()
        val ready =
            retryUntil(timeoutMs = timeoutMs, intervalMs = 100) {
                probes.incrementAndGet()
                false
            }
        val elapsedMs = (System.nanoTime() - startedAt) / NANOS_PER_MILLI

        assertFalse(ready)
        assertTrue(probes.get() > 1) { "expected several probes, got ${probes.get()}" }
        assertTrue(elapsedMs >= timeoutMs - TIMING_SLACK_MS) { "gave up after only ${elapsedMs}ms" }
        assertTrue(elapsedMs < timeoutMs + TIMING_SLACK_MS) { "overshot the deadline: ${elapsedMs}ms" }
    }

    @Test
    fun `rejects non-positive arguments instead of spinning`() {
        assertThrows(IllegalArgumentException::class.java) {
            retryUntil(timeoutMs = 100, intervalMs = 0) { true }
        }
        assertThrows(IllegalArgumentException::class.java) {
            retryUntil(timeoutMs = 0, intervalMs = 100) { true }
        }
    }

    private companion object {
        private const val NANOS_PER_MILLI = 1_000_000L

        /** Generous slack: these assertions only need to catch a broken loop, not measure it. */
        private const val TIMING_SLACK_MS = 1_000L
    }
}
