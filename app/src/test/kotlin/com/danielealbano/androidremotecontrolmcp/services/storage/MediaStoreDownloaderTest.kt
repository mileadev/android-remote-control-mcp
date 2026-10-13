package com.danielealbano.androidremotecontrolmcp.services.storage

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.util.Log
import com.danielealbano.androidremotecontrolmcp.data.model.ServerConfig
import com.danielealbano.androidremotecontrolmcp.mcp.McpToolException
import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.junit5.MockKExtension
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream

@ExtendWith(MockKExtension::class)
@DisplayName("MediaStoreDownloader")
class MediaStoreDownloaderTest {
    @MockK(relaxed = true)
    private lateinit var mockContext: Context

    @MockK(relaxed = true)
    private lateinit var mockContentResolver: ContentResolver

    @MockK(relaxed = true)
    private lateinit var mockEngine: DownloadEngine

    private val insertUri: Uri = mockk(relaxed = true)

    private lateinit var downloader: MediaStoreDownloader

    @BeforeEach
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.w(any<String>(), any<String>()) } returns 0
        every { Log.e(any(), any()) } returns 0

        every { mockContext.contentResolver } returns mockContentResolver
        every { mockContentResolver.delete(any(), any(), any()) } returns 1
        every { mockContentResolver.update(any(), any(), any(), any()) } returns 1

        downloader = MediaStoreDownloader(mockContext, mockEngine)
    }

    @AfterEach
    fun tearDown() {
        unmockkStatic(Log::class)
    }

    /** Engine stub that streams [payload] into whatever sink the downloader opens. */
    private fun stubEngineDownload(
        payload: ByteArray,
        reported: Long = payload.size.toLong(),
    ) {
        every { mockEngine.download(any(), any(), any(), any()) } answers {
            val sink = requireNotNull(arg<() -> OutputStream?>(3).invoke())
            sink.use { output -> output.write(payload) }
            reported
        }
    }

    private fun download(config: ServerConfig = ServerConfig()): Long =
        downloader.downloadToPendingUri(
            insertUri,
            "https://example.com/file.bin",
            config,
            "builtin:downloads/file.bin",
        )

    @Test
    fun `downloadToPendingUri streams bytes and clears IS_PENDING`() {
        stubEngineDownload("hello".toByteArray())
        val output = ByteArrayOutputStream()
        every { mockContentResolver.openOutputStream(eq(insertUri), eq("wt")) } returns output

        val result = download()

        assertEquals(5L, result)
        assertEquals("hello", output.toString(Charsets.UTF_8.name()))
        verify { mockContentResolver.update(eq(insertUri), any(), any(), any()) }
        verify(exactly = 0) { mockContentResolver.delete(any(), any(), any()) }
    }

    @Test
    fun `downloadToPendingUri log never leaks the URL`() {
        stubEngineDownload("x".toByteArray())
        every { mockContentResolver.openOutputStream(eq(insertUri), eq("wt")) } returns
            ByteArrayOutputStream()

        download()

        verify {
            Log.i(any(), match { it.contains("bytes to builtin:downloads/file.bin") && !it.contains("https") })
        }
    }

    @Test
    fun `downloadToPendingUri passes truncating destination stream to engine`() {
        val output = ByteArrayOutputStream()
        every { mockContentResolver.openOutputStream(eq(insertUri), eq("wt")) } returns output
        var received: OutputStream? = null
        every { mockEngine.download(any(), any(), any(), any()) } answers {
            received = requireNotNull(arg<() -> OutputStream?>(3).invoke())
            0L
        }

        download()

        assertSame(output, received)
    }

    @Test
    fun `downloadToPendingUri rethrows engine error and deletes pending entry`() {
        every { mockEngine.download(any(), any(), any(), any()) } throws
            McpToolException.ActionFailed("Download blocked: loopback address ::1 is not allowed")

        val exception = assertThrows<McpToolException.ActionFailed> { download() }

        assertTrue(exception.message!!.contains("Download blocked"))
        verify { mockContentResolver.delete(eq(insertUri), any(), any()) }
        verify(exactly = 0) { mockContentResolver.update(any(), any(), any(), any()) }
    }

    @Test
    fun `downloadToPendingUri wraps storage failure with cause and deletes entry`() {
        every { mockEngine.download(any(), any(), any(), any()) } throws IOException("destination gone")

        val exception = assertThrows<McpToolException.ActionFailed> { download() }

        assertTrue(exception.message!!.contains("Download failed: destination gone"))
        assertTrue(exception.cause is IOException)
        verify { mockContentResolver.delete(eq(insertUri), any(), any()) }
        verify(exactly = 0) { mockContentResolver.update(any(), any(), any(), any()) }
    }
}
