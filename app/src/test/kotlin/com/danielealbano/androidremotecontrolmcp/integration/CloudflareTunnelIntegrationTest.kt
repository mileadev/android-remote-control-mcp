package com.danielealbano.androidremotecontrolmcp.integration

import android.util.Log
import com.danielealbano.androidremotecontrolmcp.data.model.ServerConfig
import com.danielealbano.androidremotecontrolmcp.data.model.TunnelProviderType
import com.danielealbano.androidremotecontrolmcp.data.model.TunnelStatus
import com.danielealbano.androidremotecontrolmcp.services.tunnel.CloudflareTunnelProvider
import com.danielealbano.androidremotecontrolmcp.services.tunnel.CloudflaredBinaryResolver
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.io.PrintWriter
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.concurrent.TimeUnit

/**
 * Integration test that starts a real Cloudflare Quick Tunnel.
 *
 * Requires the `cloudflared` binary to be installed on the host machine.
 * The test is SKIPPED (not failed) if the binary is not found, so that a local run
 * without cloudflared stays green; CI installs the binary and therefore runs it for real.
 *
 * The test starts a simple standalone HTTP test server on a random local port,
 * creates a tunnel to it, and verifies the tunnel URL returns the expected
 * response.
 */
@DisplayName("CloudflareTunnelIntegrationTest")
@Timeout(value = TUNNEL_TEST_TIMEOUT_SECONDS, unit = TimeUnit.SECONDS)
class CloudflareTunnelIntegrationTest {
    private lateinit var provider: CloudflareTunnelProvider
    private var testServer: ServerSocket? = null
    private var testServerThread: Thread? = null

    @BeforeEach
    fun setUp() {
        val resolvedPath = HostCloudflareBinaryResolver().resolve()
        assumeTrue(resolvedPath != null) {
            "cloudflared binary not found on host, skipping integration test. " +
                "Install it: https://developers.cloudflare.com/" +
                "cloudflare-one/connections/connect-networks/downloads/"
        }
        val binaryPath = requireNotNull(resolvedPath)

        provider =
            CloudflareTunnelProvider(
                binaryResolver =
                    object : CloudflaredBinaryResolver {
                        override fun resolve(): String = binaryPath
                    },
            )
    }

    @AfterEach
    fun tearDown() {
        // Stop the tunnel (best-effort)
        kotlinx.coroutines.runBlocking {
            try {
                provider.stop()
            } catch (_: Exception) {
                // Ignore cleanup errors
            }
        }

        // Stop the test server
        testServerThread?.interrupt()
        testServer?.close()
    }

    @Test
    fun `tunnel connects and proxies traffic to local test server`() =
        kotlinx.coroutines.runBlocking {
            // Start a simple HTTP test server on a random local port
            val server = ServerSocket(0)
            testServer = server
            val localPort = server.localPort
            testServerThread =
                Thread {
                    while (!Thread.currentThread().isInterrupted) {
                        try {
                            val socket: Socket = server.accept()
                            handleTestRequest(socket)
                        } catch (_: java.net.SocketException) {
                            break
                        } catch (_: Exception) {
                            // Continue accepting
                        }
                    }
                }.also {
                    it.isDaemon = true
                    it.start()
                }

            // Start the tunnel
            provider.start(localPort, ServerConfig())

            // Wait for the tunnel to report Connected status
            val connectedStatus =
                withTimeout(TUNNEL_CONNECT_TIMEOUT_MS) {
                    provider.status.first { it is TunnelStatus.Connected }
                }

            assertTrue(connectedStatus is TunnelStatus.Connected)
            val connected = connectedStatus as TunnelStatus.Connected
            val tunnelUrl = connected.endpoints.single().url
            assertTrue(tunnelUrl.startsWith("https://"))
            assertTrue(tunnelUrl.contains(".trycloudflare.com"))
            assertEquals(TunnelProviderType.CLOUDFLARE, connected.providerType)

            // Cloudflare reports the tunnel Connected before its edge routes it, so the
            // tunnel is polled itself instead of sleeping a fixed 30 s and hoping.
            val response = fetchUrlWithRetry(tunnelUrl)
            assertTrue(
                response.contains(EXPECTED_RESPONSE_BODY),
                "Expected response to contain '$EXPECTED_RESPONSE_BODY' but got: $response",
            )

            // Stop the tunnel and verify status returns to Disconnected
            provider.stop()
            assertEquals(TunnelStatus.Disconnected, provider.status.value)
        }

    /**
     * Handles a single HTTP request on the test server.
     *
     * Reads the request (discarding it), then responds with a fixed body.
     * This is a minimal HTTP/1.1 responder — enough for cloudflared to proxy.
     */
    private fun handleTestRequest(socket: Socket) {
        socket.use { s ->
            val reader = s.getInputStream().bufferedReader()
            val writer = PrintWriter(s.getOutputStream(), true)

            // Read the request line and headers (discard them)
            var line: String? = reader.readLine()
            while (line != null && line.isNotEmpty()) {
                line = reader.readLine()
            }

            // Send an HTTP response
            val body = EXPECTED_RESPONSE_BODY
            writer.print("HTTP/1.1 200 OK\r\n")
            writer.print("Content-Type: text/plain\r\n")
            writer.print("Content-Length: ${body.length}\r\n")
            writer.print("Connection: close\r\n")
            writer.print("\r\n")
            writer.print(body)
            writer.flush()
        }
    }

    /**
     * Fetches [url] through the tunnel, polling until the edge serves it.
     *
     * A Cloudflare Quick Tunnel reports Connected before its edge has finished wiring the
     * route, and the record for its fresh subdomain is published asynchronously too, so the
     * first requests fail one way or another: NXDOMAIN or `Network is unreachable` while the
     * name and its address settle, 404 while the route is not published, and the whole 5xx
     * range once it is (Bad Gateway, Cloudflare Argo error 1033 → HTTP 530, edge errors
     * 520–527). None of those is a test failure, so they are retried until the
     * [TUNNEL_READY_TIMEOUT_MS] budget is spent; an HTTP status that cannot mean "not ready
     * yet" fails immediately.
     *
     * Polling the tunnel is what makes the wait both correct and bounded: a resolvable name is
     * not evidence that the edge routes traffic, so each probe asks the question the test
     * actually has — "does the tunnel serve?" — and the deadline is what stops asking. The
     * `Network is unreachable` failure that forced this rewrite came from the opposite
     * arrangement: a name that had already resolved, and a retry window too short to outlast
     * the edge's own settling.
     *
     * The budget covers what the fixed wait plus the old retry loop allowed (30 s of sleep
     * plus five attempts with growing backoff and 10 s socket timeouts, ≥60 s of waiting), so
     * replacing the sleep with a poll cannot run out of patience sooner than the code it
     * replaced. A tunnel that is already routing is reached on the first probe.
     */
    private fun fetchUrlWithRetry(url: String): String {
        var body: String? = null
        var lastFailure = "no attempt was made"
        retryUntil(TUNNEL_READY_TIMEOUT_MS, TUNNEL_PROBE_INTERVAL_MS) {
            try {
                val connection = URI(url).toURL().openConnection() as java.net.HttpURLConnection
                connection.connectTimeout = FETCH_CONNECT_TIMEOUT_MS
                connection.readTimeout = FETCH_READ_TIMEOUT_MS
                connection.requestMethod = "GET"

                val responseCode = connection.responseCode
                if (responseCode == HTTP_OK) {
                    body = connection.inputStream.bufferedReader().readText()
                    return@retryUntil true
                }

                // Retry while the tunnel is not yet fully routed.
                if (responseCode != HTTP_NOT_FOUND && responseCode !in HTTP_SERVER_ERROR_RANGE) {
                    fail<String>("Unexpected HTTP response code: $responseCode")
                }
                lastFailure = "HTTP $responseCode"
                false
            } catch (e: Exception) {
                lastFailure = e.message ?: e::class.java.simpleName
                false
            }
        }
        return body
            ?: fail("Tunnel $url served no response within $TUNNEL_READY_TIMEOUT_MS ms: $lastFailure")
    }

    companion object {
        private const val EXPECTED_RESPONSE_BODY = "tunnel-test-ok"
        private const val FETCH_CONNECT_TIMEOUT_MS = 10_000
        private const val FETCH_READ_TIMEOUT_MS = 10_000
        private const val HTTP_OK = 200
        private const val HTTP_NOT_FOUND = 404
        private val HTTP_SERVER_ERROR_RANGE = 500..599

        @JvmStatic
        @BeforeAll
        fun mockAndroidLog() {
            mockkStatic(Log::class)
            every { Log.d(any(), any()) } returns 0
            every { Log.i(any(), any()) } returns 0
            every { Log.w(any(), any<String>()) } returns 0
            every { Log.w(any(), any<String>(), any()) } returns 0
            every { Log.e(any(), any()) } returns 0
            every { Log.e(any(), any(), any()) } returns 0
        }

        @JvmStatic
        @AfterAll
        fun unmockAndroidLog() {
            unmockkStatic(Log::class)
        }
    }
}

/**
 * Timeout for the entire test class (seconds).
 *
 * Above the sum of the individual budgets — 60 s waiting for Connected, 90 s waiting for
 * the first routed response, plus a probe that can still be in flight when that budget
 * ends — so the class cap never masks the real failure with an opaque timeout.
 */
private const val TUNNEL_TEST_TIMEOUT_SECONDS = 240L

/** Timeout waiting for the tunnel to connect (milliseconds). */
private const val TUNNEL_CONNECT_TIMEOUT_MS = 60_000L

/**
 * Budget for the tunnel to start serving traffic, in milliseconds.
 *
 * Covers what the previous code allowed after Connected: the unconditional 30 s wait plus
 * five attempts with growing backoff (2+4+6+8+10 s of sleeps) and 10 s socket timeouts,
 * i.e. at least 60 s of waiting before it gave up. A tunnel that is already routing is
 * reached on the first probe, since [retryUntil] probes immediately; a tunnel that is not
 * routable yet must never be given up on sooner than the code this replaced. Pinned by
 * `RetryUntilTest`.
 */
internal const val TUNNEL_READY_TIMEOUT_MS = 90_000L

/**
 * Interval between tunnel probes (milliseconds).
 *
 * Long enough that polling a half-wired edge is cheap, short enough that a tunnel becoming
 * routable mid-budget is noticed within seconds. It also has to stay below the JVM's
 * positive DNS cache lifetime (`networkaddress.cache.ttl`, 30 s by default), so a
 * resolution taken while the name is settling cannot pin a single answer for the whole
 * budget.
 */
private const val TUNNEL_PROBE_INTERVAL_MS = 5_000L

/**
 * Polls [condition] until it holds, or [timeoutMs] elapses.
 *
 * Probes immediately, then every [intervalMs]; the final sleep is shortened so the poll
 * never waits past the deadline, and it returns as soon as [condition] holds. It is
 * bounded and interruptible (`Thread.sleep`), matching the `Thread.sleep` retry loop in
 * `fetchUrlWithRetry`, and it needs no new dependency.
 *
 * A [condition] that throws propagates its exception, leaving it to the caller to decide
 * whether a failed probe is an error or simply "not ready yet". Visible to the test
 * source set so `RetryUntilTest` can time it without touching the network.
 */
internal fun retryUntil(
    timeoutMs: Long,
    intervalMs: Long,
    condition: () -> Boolean,
): Boolean {
    require(timeoutMs > 0) { "timeoutMs must be positive, got $timeoutMs" }
    require(intervalMs > 0) { "intervalMs must be positive, got $intervalMs" }
    val deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
    var remainingMs = timeoutMs
    while (remainingMs > 0) {
        if (condition()) return true
        Thread.sleep(minOf(intervalMs, remainingMs))
        remainingMs = TimeUnit.NANOSECONDS.toMillis(deadlineNanos - System.nanoTime())
    }
    return false
}

/**
 * Resolves the cloudflared binary from the host system's PATH.
 *
 * Used in JVM integration tests where the Android-specific
 * [com.danielealbano.androidremotecontrolmcp.services.tunnel.AndroidCloudflareBinaryResolver]
 * cannot be used.
 */
class HostCloudflareBinaryResolver : CloudflaredBinaryResolver {
    override fun resolve(): String? =
        try {
            val result = ProcessBuilder("which", "cloudflared").start()
            val path =
                result.inputStream
                    .bufferedReader()
                    .readText()
                    .trim()
            if (result.waitFor() == 0 && path.isNotEmpty()) path else null
        } catch (_: Exception) {
            null
        }
}
