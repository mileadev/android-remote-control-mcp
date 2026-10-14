package com.danielealbano.androidremotecontrolmcp.services.storage

import com.danielealbano.androidremotecontrolmcp.mcp.McpToolException
import okhttp3.HttpUrl
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * Negative-heavy validation unit tests for [DownloadUrlValidator]. All cases are
 * DNS-free: private/loopback/metadata hosts are literal IPs rejected before any
 * connection is attempted, and non-literal hosts are simply not resolved here.
 */
@DisplayName("DownloadUrlValidator")
class DownloadUrlValidatorTest {
    private fun validate(url: String): HttpUrl = DownloadUrlValidator.validateAndParseHttpUrl(url)

    private fun assertInvalid(
        url: String,
        messagePart: String,
    ) {
        val exception = assertThrows<McpToolException.ActionFailed> { validate(url) }
        assertTrue(exception.message!!.contains(messagePart), "message was: ${exception.message}")
    }

    private fun assertBlocked(url: String) = assertInvalid(url, "Download blocked")

    // ─── scheme policy ───────────────────────────────────────────────────

    @Test
    fun `rejects plain http even when http downloads are enabled in config`() =
        assertInvalid("http://example.com/file.bin", "Only HTTPS downloads are allowed")

    @Test
    fun `rejects ftp scheme`() = assertInvalid("ftp://example.com/file.bin", "Only HTTPS")

    @Test
    fun `rejects file scheme`() = assertInvalid("file:///etc/passwd", "Only HTTPS")

    @Test
    fun `rejects url without scheme`() = assertInvalid("example.com/file.bin", "Invalid URL")

    @Test
    fun `rejects malformed url`() = assertInvalid("not_a_valid_url", "Invalid URL")

    @Test
    fun `rejects empty-authority https url`() = assertInvalid("https://", "Invalid URL")

    // ─── embedded credentials ────────────────────────────────────────────

    @Test
    fun `rejects userinfo with password`() {
        assertInvalid("https://user:pass@example.com/file.bin", "embedded credentials")
    }

    @Test
    fun `rejects userinfo without password`() {
        assertInvalid("https://user@example.com/file.bin", "embedded credentials")
    }

    @Test
    fun `rejects confusable host userinfo targeting private address`() =
        assertInvalid("https://example.com@10.0.0.1/file.bin", "embedded credentials")

    // ─── forbidden literal hosts ─────────────────────────────────────────

    @Test
    fun `rejects loopback v4 literal`() = assertBlocked("https://127.0.0.1/file.bin")

    @Test
    fun `rejects metadata endpoint literal`() = assertBlocked("https://169.254.169.254/file.bin")

    @Test
    fun `rejects rfc1918 literals`() {
        listOf(
            "https://10.1.2.3/file.bin",
            "https://172.16.0.1/file.bin",
            "https://172.31.255.255/file.bin",
            "https://192.168.1.1/file.bin",
        ).forEach { url -> assertBlocked(url) }
    }

    @Test
    fun `rejects loopback v6 literal`() = assertBlocked("https://[::1]/file.bin")

    @Test
    fun `rejects ipv4-mapped loopback and private literals`() {
        assertBlocked("https://[::ffff:127.0.0.1]/file.bin")
        assertBlocked("https://[::ffff:10.0.0.1]/file.bin")
    }

    @Test
    fun `rejects ipv6 link-local and ula literals`() {
        assertBlocked("https://[fe80::1]/file.bin")
        assertBlocked("https://[fc00::1]/file.bin")
    }

    @Test
    fun `rejects unspecified and broadcast literals`() {
        assertBlocked("https://0.0.0.0/file.bin")
        assertBlocked("https://255.255.255.255/file.bin")
    }

    @Test
    fun `rejects non-dotted ip encodings of loopback`() {
        assertBlocked("https://2130706433/file.bin")
        assertBlocked("https://0x7f000001/file.bin")
        assertBlocked("https://0177.0.0.1/file.bin")
    }

    @Test
    fun `rejects percent-encoded private address literals`() {
        // OkHttp decodes the host before dialling, so these reach the private address as an IP
        // literal (OkHttp then never consults PolicyDns). Validating the raw host let them through.
        assertBlocked("https://%31%32%37.0.0.1/file.bin")
        assertBlocked("https://%31%32%37.0.0.1:8443/file.bin")
        assertBlocked("https://%31%30.0.0.1/file.bin")
        assertBlocked("https://%31%37%32.16.0.1/file.bin")
        assertBlocked("https://%31%36%39.254.169.254/file.bin")
    }

    @Test
    fun `rejects percent-encoded non-canonical numeric host`() {
        assertBlocked("https://%30%78%37%66%30%30%30%30%30%31/file.bin")
    }

    @Test
    fun `rejects encoded ipv6 loopback literal`() {
        // Asserting on the other spelling, "https://%5B::1%5D/...", proves nothing here: the JDK
        // rejects it while parsing the authority, so it is refused before host validation and
        // behaves identically with or without the fix. Only the fully encoded form gets past
        // parsing and is decoded by OkHttp, so only that one exercises the host check.
        assertBlocked("https://%5B%3A%3A1%5D/file.bin")
    }

    @Test
    fun `accepts percent-encoded public hostname by its decoded form`() {
        assertEquals("example.com", validate("https://%65%78%61%6d%70%6c%65.com/file.bin").host)
    }

    // ─── allowed hosts ───────────────────────────────────────────────────

    @Test
    fun `accepts https hostname url without resolving it`() {
        val parsed = validate("https://example.com/file.bin")
        assertEquals("example.com", parsed.host)
        assertEquals("/file.bin", parsed.encodedPath)
    }

    @Test
    fun `accepts public literal address`() {
        assertEquals("8.8.8.8", validate("https://8.8.8.8/file.bin").host)
    }

    @Test
    fun `accepts custom port and preserves it`() {
        assertEquals(8443, validate("https://example.com:8443/file.bin").port)
    }

    @Test
    fun `treats hostname shaped loosely like hex as hostname`() {
        // A hex-with-dots name must NOT be treated as a literal (which could trigger a
        // synchronous DNS lookup); it is validated at connection time by PolicyDns.
        assertEquals("beef.f", validate("https://beef.f/file.bin").host)
    }

    // ─── safe log form ───────────────────────────────────────────────────

    @Test
    fun `safeLoggableUrl omits query fragment and default port`() {
        val parsed = validate("https://example.com/file.bin?token=secret#frag")
        assertEquals("https://example.com/file.bin", DownloadUrlValidator.safeLoggableUrl(parsed))
    }

    @Test
    fun `safeLoggableUrl keeps non-default port`() {
        val parsed = validate("https://example.com:8443/file.bin?token=secret")
        assertEquals("https://example.com:8443/file.bin", DownloadUrlValidator.safeLoggableUrl(parsed))
    }
}
