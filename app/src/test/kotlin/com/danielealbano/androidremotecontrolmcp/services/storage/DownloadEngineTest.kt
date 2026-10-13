package com.danielealbano.androidremotecontrolmcp.services.storage

import android.util.Log
import com.danielealbano.androidremotecontrolmcp.data.model.ServerConfig
import com.danielealbano.androidremotecontrolmcp.mcp.McpToolException
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkStatic
import io.mockk.verify
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

/** Scripted transport + response fakes for [DownloadEngine] tests. No sockets involved. */
private class FakeTransportResponse(
    override val code: Int,
    override val contentLength: Long? = null,
    override val location: String? = null,
    private val body: ByteArray = ByteArray(0),
) : DownloadHttpResponse {
    override fun bodyStream(): InputStream = ByteArrayInputStream(body)

    override fun close() = Unit
}

private class FakeTransport : DownloadHttpTransport {
    val requests = mutableListOf<HttpUrl>()
    private val scripts = ArrayDeque<(HttpUrl) -> DownloadHttpResponse>()

    fun enqueue(script: (HttpUrl) -> DownloadHttpResponse) {
        scripts.addLast(script)
    }

    override fun execute(requestUrl: HttpUrl): DownloadHttpResponse {
        requests.add(requestUrl)
        return scripts.removeFirst().invoke(requestUrl)
    }

    override fun close() = Unit
}

@DisplayName("DownloadEngine")
class DownloadEngineTest {
    private lateinit var transport: FakeTransport
    private lateinit var engine: DownloadEngine
    private val sinkFactoryOutputs: MutableList<OutputStream?> = mutableListOf()

    @BeforeEach
    fun setUp() {
        transport = FakeTransport()
        engine = DownloadEngine { transport }
        mockkStatic(Log::class)
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
    }

    @AfterEach
    fun tearDown() {
        unmockkStatic(Log::class)
    }

    private fun openSinkCapturing(): () -> OutputStream? =
        {
            val output = ByteArrayOutputStream()
            sinkFactoryOutputs.add(output)
            output
        }

    private fun download(
        url: String = "https://example.com/file.bin",
        config: ServerConfig = ServerConfig(),
    ): Long = engine.download(url, config, openSink = openSinkCapturing())

    private fun response(
        code: Int = 200,
        body: ByteArray = ByteArray(0),
        contentLength: Long? = null,
        location: String? = null,
    ) = FakeTransportResponse(code, contentLength, location, body)

    @Test
    fun `streams body to sink and returns byte count`() {
        transport.enqueue { response(body = "hello world".toByteArray(), contentLength = 11) }

        val total = download()

        assertEquals(11L, total)
        assertEquals("hello world", (sinkFactoryOutputs[0] as ByteArrayOutputStream).toString("UTF-8"))
        assertEquals(1, transport.requests.size)
    }

    @Test
    fun `follows relative redirect chain to final body`() {
        transport.enqueue { FakeTransportResponse(302, location = "/next") }
        transport.enqueue { FakeTransportResponse(200, body = "data".toByteArray()) }

        val total = download()

        assertEquals(4L, total)
        assertEquals(2, transport.requests.size)
        assertEquals("https://example.com/next", transport.requests[1].toString())
    }

    @Test
    fun `fails at redirect limit`() {
        // Five redirects are followed; the sixth hits the engine's redirect limit.
        repeat(6) {
            transport.enqueue { FakeTransportResponse(301, location = "/hop") }
        }

        val exception = assertThrows<McpToolException.ActionFailed> { download() }

        assertTrue(exception.message!!.contains("redirect limit"))
    }

    @Test
    fun `fails 3xx without location header`() {
        transport.enqueue { FakeTransportResponse(302) }

        assertThrows<McpToolException.ActionFailed> { download() }
            .message!!
            .let { assertTrue(it.contains("missing a Location header")) }
    }

    @Test
    fun `rejects redirect to private literal with zero additional requests`() {
        transport.enqueue { FakeTransportResponse(302, location = "https://169.254.169.254/latest/meta-data/") }

        val exception = assertThrows<McpToolException.ActionFailed> { download() }

        assertTrue(exception.message!!.contains("Download blocked"))
        assertEquals(1, transport.requests.size)
    }

    @Test
    fun `rejects redirect scheme downgrade without follow-up request`() {
        transport.enqueue { FakeTransportResponse(302, location = "http://example.com/file.bin") }

        val exception = assertThrows<McpToolException.ActionFailed> { download() }

        assertTrue(exception.message!!.contains("Only HTTPS downloads are allowed"))
        assertEquals(1, transport.requests.size)
    }

    @Test
    fun `rejects non-success status without opening sink`() {
        transport.enqueue { response(code = 404) }

        val exception = assertThrows<McpToolException.ActionFailed> { download() }

        assertTrue(exception.message!!.contains("HTTP status 404"))
        assertTrue(sinkFactoryOutputs.isEmpty())
    }

    @Test
    fun `rejects reported content length over limit before opening sink`() {
        transport.enqueue { response(contentLength = 2L * 1024 * 1024) }

        val exception =
            assertThrows<McpToolException.ActionFailed> {
                download(config = ServerConfig(fileSizeLimitMb = 1))
            }

        assertTrue(exception.message!!.contains("exceeds limit"))
        assertTrue(sinkFactoryOutputs.isEmpty())
    }

    @Test
    fun `rejects streamed body over limit`() {
        transport.enqueue { response(body = ByteArray(1024 * 1024 + 1)) }

        val exception =
            assertThrows<McpToolException.ActionFailed> {
                download(config = ServerConfig(fileSizeLimitMb = 1))
            }

        assertTrue(exception.message!!.contains("file size limit"))
    }

    @Test
    fun `fails when sink cannot be opened`() {
        transport.enqueue { response(body = "abc".toByteArray()) }

        val exception =
            assertThrows<McpToolException.ActionFailed> {
                engine.download("https://example.com/file.bin", ServerConfig()) { null }
            }

        assertTrue(exception.message!!.contains("Failed to open download destination"))
    }

    @Test
    fun `translates dns policy rejection into blocked message`() {
        transport.enqueue { throw ForbiddenAddressException("address ::1 is not allowed") }

        val exception = assertThrows<McpToolException.ActionFailed> { download() }

        assertTrue(exception.message!!.contains("Download blocked"))
        assertTrue(exception.cause is ForbiddenAddressException)
    }

    @Test
    fun `wraps io failure with cause`() {
        transport.enqueue { throw java.io.IOException("reset by peer") }

        val exception = assertThrows<McpToolException.ActionFailed> { download() }

        assertTrue(exception.message!!.contains("Download failed: reset by peer"))
        assertTrue(exception.cause is java.io.IOException)
    }

    @Test
    fun `logs contain no query strings`() {
        transport.enqueue { FakeTransportResponse(302, location = "/file.bin") }
        transport.enqueue { response(body = "abc".toByteArray()) }
        val infoSlot = slot<String>()
        val debugSlot = slot<String>()
        every { Log.i(any(), capture(infoSlot)) } returns 0
        every { Log.d(any(), capture(debugSlot)) } returns 0

        download(url = "https://example.com:8443/file.bin?token=supersecret")

        val logged = infoSlot.captured
        assertTrue(logged.contains("example.com:8443/file.bin"))
        assertTrue(!logged.contains("supersecret"))
        assertTrue(!debugSlot.captured.contains("supersecret"))
    }
}
