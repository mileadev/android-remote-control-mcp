package com.danielealbano.androidremotecontrolmcp.services.storage

import com.danielealbano.androidremotecontrolmcp.data.model.ServerConfig
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * Minimal response facade used by [DownloadEngine] so network semantics can be tested
 * without real sockets. Public with the public engine constructor chain.
 */
interface DownloadHttpResponse : AutoCloseable {
    /** HTTP status code of the response. */
    val code: Int

    /** Reported content length in bytes, or `null` when the server did not send one. */
    val contentLength: Long?

    /** Value of the `Location` header, or `null` when absent. */
    val location: String?

    /** Body stream of the response, or `null` for body-less responses. */
    fun bodyStream(): java.io.InputStream?

    override fun close()
}

/** OkHttp-backed [DownloadHttpResponse]. */
internal class OkHttpDownloadHttpResponse(
    private val response: Response,
) : DownloadHttpResponse {
    override val code: Int = response.code

    override val contentLength: Long? = response.body.contentLength().takeIf { it >= 0 }

    override val location: String? = response.header(RESPONSE_HEADER_LOCATION)

    override fun bodyStream(): java.io.InputStream? = response.body.byteStream()

    override fun close() = response.close()

    private companion object {
        const val RESPONSE_HEADER_LOCATION = "location"
    }
}

/**
 * Transport that executes a single request for a download hop and returns the response.
 * Redirects are never followed automatically; [DownloadEngine] revalidates each hop.
 */
interface DownloadHttpTransport : AutoCloseable {
    fun execute(requestUrl: HttpUrl): DownloadHttpResponse

    override fun close()
}

/** OkHttp-backed [DownloadHttpTransport]. */
internal class OkHttpDownloadTransport(
    private val client: OkHttpClient,
) : DownloadHttpTransport {
    override fun execute(requestUrl: HttpUrl): DownloadHttpResponse =
        OkHttpDownloadHttpResponse(
            client
                .newCall(
                    Request
                        .Builder()
                        .url(requestUrl)
                        .build(),
                ).execute(),
        )

    override fun close() {
        // Per-download client holds no per-call state beyond its shared connection pool.
    }
}

/**
 * [Dns] wrapper that enforces a [DownloadAddressPolicy] on every address the client is
 * about to connect to. Because OkHttp connects exactly to the addresses returned here
 * (including literal IP hosts), the allowlist cannot be bypassed by DNS rebinding or
 * by late resolution inside the connection stack.
 */
internal class PolicyDns(
    private val delegate: Dns,
    private val policy: DownloadAddressPolicy = PublicInternetAddressPolicy,
) : Dns {
    @Throws(UnknownHostException::class)
    override fun lookup(hostname: String): List<InetAddress> {
        val addresses = delegate.lookup(hostname)
        addresses.forEach { address ->
            try {
                policy.requireAllowed(address)
            } catch (e: ForbiddenAddressException) {
                throw ForbiddenAddressException("${e.message} (host: \"$hostname\")", e)
            }
        }
        return addresses
    }
}

/**
 * [DownloadHttpTransport] factory bound to the download hardening configuration.
 * Public with [DownloadEngine] (public constructor chain through Hilt).
 */
fun interface DownloadTransportFactory {
    fun create(config: ServerConfig): DownloadHttpTransport
}

/** Production factory: strict TLS, strict address policy, config-driven timeouts. */
class SecureDownloadTransportFactory
    @Inject
    constructor() : DownloadTransportFactory {
        override fun create(config: ServerConfig): DownloadHttpTransport {
            val okHttpTransport = OkHttpDownloadTransport(SecureDownloadClient.create(config))
            return okHttpTransport
        }
    }

/**
 * Hardened [OkHttpClient] factory for downloads.
 *
 * Guarantees enforced by construction:
 *   - redirect following disabled (each hop revalidated by [DownloadEngine]);
 *   - every connection target passes [PublicInternetAddressPolicy] (via [PolicyDns],
 *     bound to the actual connection attempt - no resolve/connect TOCTOU window);
 *   - platform trust store and default hostname verifier only, TLS always verified;
 *   - timeouts derived from [ServerConfig.downloadTimeoutSeconds] (a wall-clock call
 *     timeout bounds the whole download, not just individual sockets).
 *
 * The optional [sslSocketFactory]/[trustManager] pair exists solely so lab integration
 * tests can point the hardened client at a local TLS server with a generated CA;
 * production callers omit it and keep platform trust.
 */
internal object SecureDownloadClient {
    private val baseClient: OkHttpClient by lazy { OkHttpClient() }

    fun create(
        config: ServerConfig,
        dns: Dns = Dns.SYSTEM,
        policy: DownloadAddressPolicy = PublicInternetAddressPolicy,
        sslSocketFactory: SSLSocketFactory? = null,
        trustManager: X509TrustManager? = null,
    ): OkHttpClient {
        val timeoutSeconds = config.downloadTimeoutSeconds.toLong()
        val builder =
            baseClient
                .newBuilder()
                .dns(PolicyDns(dns, policy))
                .followRedirects(false)
                .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .writeTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .callTimeout(timeoutSeconds, TimeUnit.SECONDS)
        if (sslSocketFactory != null && trustManager != null) {
            builder.sslSocketFactory(sslSocketFactory, trustManager)
        }
        return builder.build()
    }
}
