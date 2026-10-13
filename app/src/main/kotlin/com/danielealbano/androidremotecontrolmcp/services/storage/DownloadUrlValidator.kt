package com.danielealbano.androidremotecontrolmcp.services.storage

import com.danielealbano.androidremotecontrolmcp.mcp.McpToolException
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.net.InetAddress
import java.net.MalformedURLException
import java.net.URL
import java.net.UnknownHostException

/**
 * Strict, hardening-focused validation for download URLs.
 *
 * Per 02-REPOSITORY-HARDENING.md (H-04) downloads are HTTPS-only, must not carry embedded
 * credentials (which would also enable `https://attacker.com@169.254.169.254/` confusable
 * targets), reject literal private/link-local/loopback/metadata hosts before any connection
 * is attempted, and leave name-based host policy to [PolicyDns], which binds the allowlist
 * to the addresses OkHttp actually connects to (no DNS-rebinding TOCTOU window).
 *
 * Plain HTTP is no longer accepted, so [ServerConfig.allowHttpDownloads]
 * no longer influences downloads; HTTPS keeps full certificate and hostname verification.
 */
internal object DownloadUrlValidator {
    /**
     * Validates [url] and parses it into an [HttpUrl] for transport use.
     *
     * @param policy address allowlist applied to literal hosts; the production default is
     *   [PublicInternetAddressPolicy], lab integration tests may inject a loopback-only
     *   policy to exercise real TLS against a local server.
     * @throws McpToolException.ActionFailed when the URL is malformed, uses a non-HTTPS
     *         scheme, carries embedded credentials, or points at a forbidden literal IP.
     */
    internal fun validateAndParseHttpUrl(
        url: String,
        policy: DownloadAddressPolicy = PublicInternetAddressPolicy,
    ): HttpUrl {
        val parsedUrl = parseUrl(url)
        requireNoEmbeddedCredentials(parsedUrl)
        requireHttpsScheme(parsedUrl)
        val httpUrl = url.toHttpUrlOrNull() ?: throw McpToolException.ActionFailed("Invalid URL: $url")
        // Validate the host OkHttp will actually dial, not the raw host `java.net.URL` reports:
        // the two disagree on percent-encoded and other non-canonical spellings, so validating
        // the raw form let `https://%31%32%37.0.0.1/` reach the loopback address that OkHttp
        // resolves as an IP literal (and therefore without ever consulting [PolicyDns]).
        requirePublicLiteralHost(httpUrl.host, policy)

        return httpUrl
    }

    /**
     * Redacted form of [url] safe for logs: scheme, host, port and path only - never the
     * query string or fragment, which may carry secrets.
     */
    internal fun safeLoggableUrl(url: HttpUrl): String {
        val authority = if (url.port == DEFAULT_HTTPS_PORT) url.host else "${url.host}:${url.port}"
        return "${url.scheme}://$authority${url.encodedPath}"
    }

    private fun parseUrl(url: String): URL =
        try {
            URL(url)
        } catch (e: MalformedURLException) {
            throw McpToolException.ActionFailed("Invalid URL: $url", e)
        }

    private fun requireNoEmbeddedCredentials(parsedUrl: URL) {
        if (parsedUrl.userInfo != null) {
            throw McpToolException.ActionFailed(
                "Download URLs must not contain embedded credentials (user:pass@host).",
            )
        }
    }

    private fun requireHttpsScheme(parsedUrl: URL) {
        if (parsedUrl.protocol != HTTPS_SCHEME) {
            throw McpToolException.ActionFailed("Only HTTPS downloads are allowed; use an https:// URL.")
        }
    }

    private fun requirePublicLiteralHost(
        host: String,
        policy: DownloadAddressPolicy,
    ) {
        val literal = host.removePrefix("[").removeSuffix("]")
        when {
            literal.contains(':') || isCanonicalIpv4DottedQuad(literal) -> {
                requirePublicAddress(literal, host, policy)
            }

            LITERAL_IP_PATTERN.matches(literal) -> {
                // Numeric encodings OkHttp or the platform resolver could interpret as a
                // private IP (octal, hex, decimal integer). Never a legitimate public host
                // name, so reject without giving any resolver a chance to expand it.
                throw McpToolException.ActionFailed(
                    "Download blocked: numeric download hosts must use canonical decimal" +
                        " dotted-quad IPv4 (got: $host).",
                )
            }
        }
    }

    private fun requirePublicAddress(
        literal: String,
        host: String,
        policy: DownloadAddressPolicy,
    ) {
        val address =
            try {
                InetAddress.getByName(literal)
            } catch (e: UnknownHostException) {
                throw McpToolException.ActionFailed("Invalid download host: $host", e)
            }
        try {
            policy.requireAllowed(address)
        } catch (e: ForbiddenAddressException) {
            throw McpToolException.ActionFailed("Download blocked: ${e.message}", e)
        }
    }

    private fun isCanonicalIpv4DottedQuad(host: String): Boolean {
        val parts = host.split(".")
        if (parts.size != IPV4_PART_COUNT) return false
        return parts.all { part ->
            part.length in IPV4_PART_MIN_LENGTH..IPV4_PART_MAX_LENGTH &&
                part.all { character: Char -> character.isDigit() } &&
                (part.length == 1 || part[0] != '0') &&
                part.toInt() <= MAX_IPV4_OCTET
        }
    }

    private const val HTTPS_SCHEME = "https"
    private const val DEFAULT_HTTPS_PORT = 443
    private const val IPV4_PART_COUNT = 4
    private const val IPV4_PART_MIN_LENGTH = 1
    private const val IPV4_PART_MAX_LENGTH = 3
    private const val MAX_IPV4_OCTET = 255
    private val LITERAL_IP_PATTERN = Regex("^(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:\\.(?:0[xX][0-9a-fA-F]+|[0-9]+))*$")
}
