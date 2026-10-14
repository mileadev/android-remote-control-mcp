package com.danielealbano.androidremotecontrolmcp.services.storage

import android.util.Log
import com.danielealbano.androidremotecontrolmcp.data.model.ServerConfig
import com.danielealbano.androidremotecontrolmcp.mcp.McpToolException
import okhttp3.HttpUrl
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject

/**
 * Hardened download execution: HTTPS-only (validated on every hop), manually followed
 * redirects that are revalidated against the address policy, content-length and streaming
 * size caps, config-driven timeouts supplied by [DownloadTransportFactory], and
 * log output restricted to a redacted URL form without query or fragment.
 *
 * Public because [FileOperationProviderImpl] takes it in its public constructor via Hilt;
 * internal transport details stay encapsulated.
 */
class DownloadEngine
    @Inject
    constructor(
        private val transportFactory: DownloadTransportFactory,
    ) {
        /**
         * Downloads [url] into the stream opened by [openSink], which is invoked only after
         * status, redirect and declared content-length checks pass. Returns bytes written.
         *
         * @param addressPolicy per-hop address allowlist; production callers keep the default
         *   [PublicInternetAddressPolicy]. Lab integration tests inject a loopback-only policy
         *   so the hardened pipeline can be exercised against a local TLS server end to end.
         * @throws McpToolException.ActionFailed for any blocked, oversized or failed download.
         */
        @Suppress("TooGenericExceptionCaught")
        fun download(
            url: String,
            config: ServerConfig,
            addressPolicy: DownloadAddressPolicy = PublicInternetAddressPolicy,
            openSink: () -> OutputStream?,
        ): Long =
            try {
                transportFactory
                    .create(config)
                    .use { transport -> runHops(transport, url, config, addressPolicy, openSink) }
            } catch (e: McpToolException) {
                throw e
            } catch (e: ForbiddenAddressException) {
                throw McpToolException.ActionFailed("Download blocked: ${e.message}", e)
            } catch (e: Exception) {
                // The engine is the last translation boundary: any transport/IO failure must surface
                // as a tool-facing ActionFailed instead of escaping as an arbitrary exception.
                throw McpToolException.ActionFailed("Download failed: ${e.message ?: "Unknown error"}", e)
            }

        private fun runHops(
            transport: DownloadHttpTransport,
            url: String,
            config: ServerConfig,
            addressPolicy: DownloadAddressPolicy,
            openSink: () -> OutputStream?,
        ): Long {
            val limitBytes = config.fileSizeLimitMb.toLong() * BYTES_PER_MB
            var currentUrl = url
            var redirectsRemaining = MAX_REDIRECTS

            while (true) {
                val requestUrl = DownloadUrlValidator.validateAndParseHttpUrl(currentUrl, addressPolicy)
                transport.execute(requestUrl).use { response ->
                    val location = response.location
                    if (response.code in REDIRECT_STATUS_CODES) {
                        if (location == null) {
                            throw McpToolException.ActionFailed(
                                "Download redirect response ${response.code} is missing a Location header.",
                            )
                        }
                        if (redirectsRemaining == 0) {
                            throw McpToolException.ActionFailed(
                                "Download exceeded the redirect limit of $MAX_REDIRECTS hops.",
                            )
                        }
                        redirectsRemaining--
                        val next = resolveRedirectTarget(requestUrl, location)
                        Log.d(TAG, "Following download redirect to ${DownloadUrlValidator.safeLoggableUrl(next)}")
                        currentUrl = next.toString()
                    } else {
                        return finishDownload(response, requestUrl, config, limitBytes, openSink)
                    }
                }
            }
        }

        private fun resolveRedirectTarget(
            base: HttpUrl,
            location: String,
        ): HttpUrl =
            base.resolve(location) ?: throw McpToolException.ActionFailed(
                "Download redirect location is not a valid URL: $location",
            )

        private fun finishDownload(
            response: DownloadHttpResponse,
            requestUrl: HttpUrl,
            config: ServerConfig,
            limitBytes: Long,
            openSink: () -> OutputStream?,
        ): Long {
            requireSuccessfulResponse(response, config, limitBytes)

            val sink =
                openSink() ?: throw McpToolException.ActionFailed(
                    "Failed to open download destination for writing.",
                )

            return sink.use { output ->
                val total = response.bodyStream()?.let { copyWithLimit(it, output, limitBytes) } ?: 0L
                Log.i(TAG, "Downloaded $total bytes from ${DownloadUrlValidator.safeLoggableUrl(requestUrl)}")
                total
            }
        }

        private fun requireSuccessfulResponse(
            response: DownloadHttpResponse,
            config: ServerConfig,
            limitBytes: Long,
        ) {
            val code = response.code
            if (code !in SUCCESS_STATUS_MIN..SUCCESS_STATUS_MAX) {
                throw McpToolException.ActionFailed("Download failed with HTTP status $code.")
            }

            val contentLength = response.contentLength
            if (contentLength != null && contentLength > limitBytes) {
                throw McpToolException.ActionFailed(
                    "Server reports file size of $contentLength bytes, exceeds limit of ${config.fileSizeLimitMb} MB.",
                )
            }
        }

        private fun copyWithLimit(
            body: InputStream,
            output: OutputStream,
            limitBytes: Long,
        ): Long {
            val buffer = ByteArray(DOWNLOAD_BUFFER_SIZE)
            var total = 0L
            body.use { input ->
                while (true) {
                    val read = input.read(buffer)
                    if (read == EOF) break
                    total += read
                    if (total > limitBytes) {
                        throw McpToolException.ActionFailed(
                            "Download exceeds the configured file size limit of ${limitBytes / BYTES_PER_MB} MB.",
                        )
                    }
                    output.write(buffer, 0, read)
                }
            }
            output.flush()
            return total
        }

        private companion object {
            const val TAG = "MCP:DownloadEngine"
            const val BYTES_PER_MB = 1024L * 1024L
            const val DOWNLOAD_BUFFER_SIZE = 8192
            const val MAX_REDIRECTS = 5
            const val EOF = -1
            const val SUCCESS_STATUS_MIN = 200
            const val SUCCESS_STATUS_MAX = 299

            val REDIRECT_STATUS_CODES = setOf(301, 302, 303, 307, 308)
        }
    }
