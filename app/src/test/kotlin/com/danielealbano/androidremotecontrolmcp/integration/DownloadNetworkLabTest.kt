package com.danielealbano.androidremotecontrolmcp.integration

import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.data.model.ServerConfig
import com.danielealbano.androidremotecontrolmcp.mcp.McpToolException
import com.danielealbano.androidremotecontrolmcp.mcp.tools.DownloadFromUrlHandler
import com.danielealbano.androidremotecontrolmcp.services.storage.DownloadAddressPolicy
import com.danielealbano.androidremotecontrolmcp.services.storage.DownloadEngine
import com.danielealbano.androidremotecontrolmcp.services.storage.DownloadTransportFactory
import com.danielealbano.androidremotecontrolmcp.services.storage.ForbiddenAddressException
import com.danielealbano.androidremotecontrolmcp.services.storage.OkHttpDownloadTransport
import com.danielealbano.androidremotecontrolmcp.services.storage.PublicInternetAddressPolicy
import com.danielealbano.androidremotecontrolmcp.services.storage.SecureDownloadClient
import com.danielealbano.androidremotecontrolmcp.services.storage.SecureDownloadTransportFactory
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.Dns
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InterruptedIOException
import java.math.BigInteger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

private const val QUERY_TOKEN = "S3CR3T-QUERY-TOKEN-42"
private const val LOOPBACK_HOST = "127.0.0.1"
private const val PAYLOAD_BYTES = 3072
private const val MAX_TEST_SIZE_BYTES = 1048576L
private val CA_SUBJECT = X500Name("CN=Android MCP Lab Test CA")
private val LEAF_SUBJECT = X500Name("CN=android-mcp-lab-server.internal")
private const val MISMATCH_SAN_HOST = "lab-not-this-host.internal"

/**
 * A locally generated X.509 identity: an optional signing CA plus the leaf certificate that a
 * loopback HTTPS server presents.
 */
private class LabCertificateMaterial(
    val caCertificate: X509Certificate?,
    val leafCertificate: X509Certificate,
    val leafKey: PrivateKey,
)

/** Loopback HTTPS test server plus request counters and response configuration for handlers. */
private class LoopbackServerHandle(
    val httpsServer: HttpsServer,
) {
    val port: Int = httpsServer.address.port
    val requestCount = AtomicLong(0)
    var delayMillis: Long = 0L
    var declaredContentLength: Long? = null

    /** When there is no declared length, respond chunked (no Content-Length header) if set. */
    var chunkedResponse: Boolean = false
    var respondWithBody: ByteArray = ByteArray(PAYLOAD_BYTES) { index: Int -> (index % Byte.MAX_VALUE).toByte() }

    fun baseUrl(path: String): String = "https://$LOOPBACK_HOST:$port$path"

    fun loopbackNameUrl(path: String): String = "https://localhost:$port$path"

    fun stop() {
        httpsServer.stop(0)
    }
}

/** Resolver stub mapping every queried host onto the loopback address (simulated DNS rebinding). */
private class RebindingDns : Dns {
    override fun lookup(hostname: String): List<InetAddress> = listOf(InetAddress.getByName(LOOPBACK_HOST))
}

/**
 * Real-TLS integration tests for the hardened download pipeline (acceptance item H-04, gates
 * V06/V11). All traffic targets a local HTTPS server; public-internet policy negatives run the
 * production transport untouched, while positive downloads inject a loopback-only
 * [DownloadAddressPolicy] so the production client (timeouts, no redirects, TLS verification)
 * still applies end to end. Every certificate is generated in-file with BouncyCastle.
 */
@DisplayName("Download network lab hardening")
class DownloadNetworkLabTest {
    @BeforeEach
    fun setUp() {
        McpIntegrationTestHelper.mockAndroidLog()
    }

    @AfterEach
    fun tearDown() {
        McpIntegrationTestHelper.unmockAndroidLog()
    }

    // ─────────────────────────────────────────────────────────────────────
    // Mandated acceptance tests
    // ─────────────────────────────────────────────────────────────────────

    @Test
    fun deniesPrivateIpv4Ipv6AndIpv4Mapped() {
        val engine = productionEngine()
        val config = ServerConfig()
        val serverHandle = startLoopbackServer(::serveLoopedBackPayload)

        requireDownloadBlocked(engine, serverHandle.baseUrl("/secret-path"), config, serverHandle)
            .let { failure -> assertTrue(failure.message!!.contains("Download blocked"), failure.message) }
        requireDownloadBlocked(engine, "https://10.1.2.3/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://172.16.9.9/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://192.168.1.7/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://169.254.169.254/latest/meta-data/", config, serverHandle)
            .let { failure -> assertTrue(failure.message!!.contains("Download blocked"), failure.message) }
        requireDownloadBlocked(engine, "https://[::1]/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://[::ffff:10.0.0.2]/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://[::ffff:127.0.0.1]/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://[::ffff:169.254.169.254]/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://2130706433/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://0177.0.0.1/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://0x7f.0x0.0x0.0x1/data.bin", config, serverHandle)
        requireDownloadBlocked(engine, "https://127.0.0.1:1@169.254.169.254/x", config, serverHandle)
            .let { failure -> assertTrue(failure.message!!.contains("embedded credentials"), failure.message) }

        // Loopback reached through host resolution ("localhost") must be refused at the
        // connection layer before any socket opens: zero exchanges reach the local server.
        requireDownloadBlocked(engine, serverHandle.loopbackNameUrl("/via-localhost"), config, serverHandle)
            .let { failure -> assertTrue(failure.message!!.contains("Download blocked"), failure.message) }
        serverHandle.stop()
    }

    @Test
    fun deniesRedirectToInternalAndDnsRebinding() {
        val trustedMaterial = labCertificateMaterial(expiredLeaf = false, wrongSansLeaf = false)
        val trustedEngine = loopbackEngine(trustedMaterial.caCertificate!!)
        val serverHandle = startLoopbackServer(::serveRedirect, material = trustedMaterial)
        val config = ServerConfig()

        // Hop 1 succeeds against the loopback server; hop 2 points at an internal address and
        // must be refused with exactly one outbound request observed (no follow of the redirect).
        requireDownloadBlocked(
            trustedEngine,
            serverHandle.baseUrl("/redirect-to-metadata"),
            config,
            serverHandle,
            expectedExchanges = 1,
            policy = loopbackOnlyPolicy(),
        ).let { failure -> assertTrue(failure.message!!.contains("Download blocked"), failure.message) }
        requireDownloadBlocked(
            trustedEngine,
            // requestCount is cumulative across the two redirect probes above.
            serverHandle.baseUrl("/redirect-to-plain-http"),
            config,
            serverHandle,
            expectedExchanges = 2,
            policy = loopbackOnlyPolicy(),
        ).let { failure ->
            assertTrue(failure.message!!.contains("Only HTTPS downloads are allowed"), failure.message)
        }

        // DNS rebinding: the resolver hands the public-looking name a private loopback address;
        // the address policy bound to the connection refuses the hop before any socket opens.
        requireDownloadBlocked(
            rebindingEngine(),
            // requestCount is cumulative with the two redirect probes above.
            "https://rebind.internal.example/data.bin",
            config,
            serverHandle,
            expectedExchanges = 2,
        ).let { failure -> assertTrue(failure.message!!.contains("Download blocked"), failure.message) }
        serverHandle.stop()
    }

    @Test
    fun deniesCertMismatchExpiredSelfSigned() {
        val config = ServerConfig()

        val loopbackPolicy = loopbackOnlyPolicy()
        // 1. Self-signed leaf with plain platform trust: untrusted chain must fail the handshake.
        val selfSignedHandle = startLoopbackServer(::serveLoopedBackPayload, material = selfSignedOnlyMaterial())
        val selfSignedFailure =
            assertThrows<McpToolException.ActionFailed> {
                loopbackEngine().download(
                    selfSignedHandle.baseUrl("/data.bin"),
                    config,
                    loopbackPolicy,
                ) { ByteArrayOutputStream() }
            }
        assertInstanceOf(SSLException::class.java, selfSignedFailure.cause)
        selfSignedHandle.stop()

        // 2. CA-signed but expired leaf, lab CA trusted via a per-client trust manager:
        // expiry must fail validation.
        val expiredMaterial = labCertificateMaterial(expiredLeaf = true, wrongSansLeaf = false)
        val expiredHandle = startLoopbackServer(::serveLoopedBackPayload, material = expiredMaterial)
        val expiredFailure =
            assertThrows<McpToolException.ActionFailed> {
                loopbackEngine(expiredMaterial.caCertificate!!).download(
                    expiredHandle.baseUrl("/data.bin"),
                    config,
                    loopbackPolicy,
                ) { ByteArrayOutputStream() }
            }
        assertInstanceOf(SSLException::class.java, expiredFailure.cause)
        val expiredText = expiredFailure.cause?.message ?: ""
        assertTrue(expiredText.contains("expired") || expiredText.contains("validity check"), expiredFailure.message!!)
        expiredHandle.stop()

        // 3. CA-signed, trusted, but certificate issued for a different host: name mismatch fails.
        val mismatchMaterial = labCertificateMaterial(expiredLeaf = false, wrongSansLeaf = true)
        val mismatchHandle = startLoopbackServer(::serveLoopedBackPayload, material = mismatchMaterial)
        val mismatchFailure =
            assertThrows<McpToolException.ActionFailed> {
                loopbackEngine(mismatchMaterial.caCertificate!!).download(
                    mismatchHandle.baseUrl("/data.bin"),
                    config,
                    loopbackPolicy,
                ) { ByteArrayOutputStream() }
            }
        val mismatchText = mismatchFailure.cause?.message ?: ""
        assertTrue(mismatchFailure.cause != null, mismatchFailure.message!!)
        assertTrue(mismatchText.contains("not verified") || mismatchText.contains("hostname"), mismatchText)
        mismatchHandle.stop()
    }

    @Test
    fun enforcesSizeTimeoutAndNoSecretLogging() {
        val trustedMaterial = labCertificateMaterial(expiredLeaf = false, wrongSansLeaf = false)
        val caCertificate = trustedMaterial.caCertificate!!
        val serverHandle = startLoopbackServer(::serveLoopedBackPayload, material = trustedMaterial)
        val engine = loopbackEngine(caCertificate)

        val payload = ByteArray(PAYLOAD_BYTES) { index: Int -> (index % Byte.MAX_VALUE).toByte() }
        val loopbackPolicy = loopbackOnlyPolicy()
        serverHandle.respondWithBody = payload
        val successSink = ByteArrayOutputStream()
        val successConfig = ServerConfig(downloadTimeoutSeconds = 30, fileSizeLimitMb = 1)
        val downloaded =
            engine.download(
                serverHandle.baseUrl("/file.bin?token=$QUERY_TOKEN"),
                successConfig,
                loopbackPolicy,
            ) { successSink }
        assertEquals(PAYLOAD_BYTES.toLong(), downloaded)
        assertTrue(successSink.toByteArray().contentEquals(payload))

        val oversizedConfig = ServerConfig(downloadTimeoutSeconds = 30, fileSizeLimitMb = 1)
        serverHandle.declaredContentLength = 3 * MAX_TEST_SIZE_BYTES
        val declaredFailure =
            assertThrows<McpToolException.ActionFailed> {
                engine.download(
                    serverHandle.baseUrl("/declared-oversize.bin"),
                    oversizedConfig,
                    loopbackPolicy,
                ) { ByteArrayOutputStream() }
            }
        assertTrue(declaredFailure.message!!.contains("Server reports file size"), declaredFailure.message)

        assertStreamedBodySizeCapEnforced(engine, serverHandle, loopbackPolicy, payload)

        serverHandle.delayMillis = 3500L
        val slowConfig = ServerConfig(downloadTimeoutSeconds = 1, fileSizeLimitMb = 5)
        val timeoutFailure =
            assertThrows<McpToolException.ActionFailed> {
                engine.download(
                    serverHandle.baseUrl("/slow.bin"),
                    slowConfig,
                    loopbackPolicy,
                ) { ByteArrayOutputStream() }
            }
        assertInstanceOf(InterruptedIOException::class.java, timeoutFailure.cause)

        // The no-secret probe downloads live against the server, so stop it only afterwards.
        serverHandle.delayMillis = 0L
        assertLoggedCallsCarryNoSecrets(serverHandle, caCertificate)
        serverHandle.stop()
    }

    @Test
    fun deniesToolInHardenedVariant() =
        runTest {
            val deps = McpIntegrationTestHelper.createMockDependencies()

            if (BuildConfig.LAB_HARDENED) {
                McpIntegrationTestHelper.withTestApplication(deps) { client, _ ->
                    val names = client.listTools().tools.map { it.name }
                    assertTrue(
                        names.none { it.contains("download_from_url") },
                        "download_from_url must be absent from the hardened lab tool list",
                    )
                }
                // Defense in depth: dispatching the handler directly must also be denied (V11).
                val handler = DownloadFromUrlHandler(deps.fileOperationProvider)
                val error =
                    runCatching {
                        handler.execute(
                            JsonObject(
                                mapOf(
                                    "location_id" to JsonPrimitive("loc1"),
                                    "path" to JsonPrimitive("file.txt"),
                                    "url" to JsonPrimitive("https://example.com/file.txt"),
                                ),
                            ),
                        )
                    }.exceptionOrNull()
                assertInstanceOf(McpToolException.PermissionDenied::class.java, error)
            } else {
                McpIntegrationTestHelper.withTestApplication(deps) { client, _ ->
                    val names = client.listTools().tools.map { it.name }
                    assertTrue(
                        names.contains("android_download_from_url"),
                        "gms/foss builds must keep download_from_url registered",
                    )
                }
            }
        }

    // ─────────────────────────────────────────────────────────────────────
    // Assertions and engines
    // ─────────────────────────────────────────────────────────────────────

    private fun requireDownloadBlocked(
        engine: DownloadEngine,
        url: String,
        config: ServerConfig,
        serverHandle: LoopbackServerHandle,
        expectedExchanges: Long = 0,
        policy: DownloadAddressPolicy = PublicInternetAddressPolicy,
    ): McpToolException.ActionFailed {
        val failure =
            assertThrows<McpToolException.ActionFailed> {
                engine.download(url, config, policy) { ByteArrayOutputStream() }
            }
        assertTrue(
            failure.message!!.contains("Download blocked") ||
                failure.message!!.contains("Only HTTPS downloads are allowed") ||
                failure.message!!.contains("embedded credentials") ||
                failure.message!!.contains("Invalid"),
            failure.message!!,
        )
        assertEquals(
            expectedExchanges,
            serverHandle.requestCount.get(),
            "Rejected download must produce no outbound request to the forbidden destination (URL: $url)",
        )
        return failure
    }

    /** Serves a chunked response (no Content-Length) 1.5x over the cap and expects the streaming cap. */
    private fun assertStreamedBodySizeCapEnforced(
        engine: DownloadEngine,
        serverHandle: LoopbackServerHandle,
        policy: DownloadAddressPolicy,
        payload: ByteArray,
    ) {
        serverHandle.declaredContentLength = null
        serverHandle.chunkedResponse = true
        serverHandle.respondWithBody =
            ByteArray((MAX_TEST_SIZE_BYTES * 3 / 2).toInt()) { index: Int -> (index % Byte.MAX_VALUE).toByte() }
        val streamedConfig = ServerConfig(downloadTimeoutSeconds = 30, fileSizeLimitMb = 1)
        val streamedFailure =
            assertThrows<McpToolException.ActionFailed> {
                engine.download(
                    serverHandle.baseUrl("/streamed-oversize.bin"),
                    streamedConfig,
                    policy,
                ) { ByteArrayOutputStream() }
            }
        assertTrue(
            streamedFailure.message!!.contains("Download exceeds the configured file size limit"),
            streamedFailure.message,
        )
        serverHandle.chunkedResponse = false
        serverHandle.respondWithBody = payload
    }

    private fun assertLoggedCallsCarryNoSecrets(
        serverHandle: LoopbackServerHandle,
        caCertificate: X509Certificate?,
    ) {
        unmockkStatic(android.util.Log::class)
        val loggedMessages = mutableListOf<String>()
        mockkStatic(android.util.Log::class)
        every { android.util.Log.i(any(), any()) } answers {
            loggedMessages.add(arg<String>(1))
            0
        }
        every { android.util.Log.d(any(), any()) } answers {
            loggedMessages.add(arg<String>(1))
            0
        }
        every { android.util.Log.w(any<String>(), any<String>()) } answers {
            loggedMessages.add(arg<String>(1))
            0
        }
        every { android.util.Log.e(any(), any()) } answers {
            loggedMessages.add(arg<String>(1))
            0
        }
        try {
            val engine = loopbackEngine(caCertificate)
            val config = ServerConfig(downloadTimeoutSeconds = 30, fileSizeLimitMb = 1)
            engine.download(
                serverHandle.baseUrl("/logged.bin?token=$QUERY_TOKEN"),
                config,
                loopbackOnlyPolicy(),
            ) { ByteArrayOutputStream() }
        } finally {
            unmockkStatic(android.util.Log::class)
            McpIntegrationTestHelper.mockAndroidLog()
        }

        val allLogged = loggedMessages.joinToString(separator = "\n")
        assertTrue(loggedMessages.isNotEmpty(), "Download path must log for the no-secret assertion to be meaningful")
        assertTrue(!allLogged.contains(QUERY_TOKEN), allLogged)
        assertTrue(!allLogged.contains("token="), allLogged)
        assertTrue(
            loggedMessages.any { it.contains("Downloaded") && it.contains(LOOPBACK_HOST) },
            allLogged,
        )
    }

    private fun productionEngine(): DownloadEngine = DownloadEngine(SecureDownloadTransportFactory())

    private fun rebindingEngine(): DownloadEngine =
        DownloadEngine(
            DownloadTransportFactory { config: ServerConfig ->
                OkHttpDownloadTransport(SecureDownloadClient.create(config, dns = RebindingDns()))
            },
        )

    private fun loopbackEngine(caCertificate: X509Certificate? = null): DownloadEngine =
        DownloadEngine(
            DownloadTransportFactory { config: ServerConfig ->
                val socketPair = caCertificate?.let(::labTrustedSocketPair)
                OkHttpDownloadTransport(
                    SecureDownloadClient.create(
                        config,
                        dns = loopbackOnlyDns(),
                        policy = loopbackOnlyPolicy(),
                        sslSocketFactory = socketPair?.first,
                        trustManager = socketPair?.second,
                    ),
                )
            },
        )

    private fun loopbackOnlyDns(): Dns = Dns { hostname: String -> listOf(InetAddress.getByName(LOOPBACK_HOST)) }

    private fun loopbackOnlyPolicy(): DownloadAddressPolicy =
        DownloadAddressPolicy { address: InetAddress ->
            if (!address.isLoopbackAddress) {
                throw ForbiddenAddressException("Lab test policy permits only loopback, saw $address")
            }
        }

    // ─────────────────────────────────────────────────────────────────────
    // HTTPS server harness
    // ─────────────────────────────────────────────────────────────────────

    private fun startLoopbackServer(
        handler: (HttpExchange, LoopbackServerHandle) -> Unit,
        material: LabCertificateMaterial = labCertificateMaterial(expiredLeaf = false, wrongSansLeaf = false),
    ): LoopbackServerHandle {
        val httpsServer = createHttpsServer(material)
        val serverHandle = LoopbackServerHandle(httpsServer)
        httpsServer.createContext("/") { exchange ->
            serverHandle.requestCount.incrementAndGet()
            try {
                if (serverHandle.delayMillis > 0L) {
                    Thread.sleep(serverHandle.delayMillis)
                }
                handler(exchange, serverHandle)
            } finally {
                exchange.close()
            }
        }
        httpsServer.executor = Executors.newCachedThreadPool()
        httpsServer.start()
        return serverHandle
    }

    private fun createHttpsServer(material: LabCertificateMaterial): HttpsServer {
        val storePassword = "labserver".toCharArray()
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(null, storePassword)
        keyStore.setKeyEntry("labserver", material.leafKey, storePassword, arrayOf(material.leafCertificate))
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, storePassword)
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(keyManagerFactory.keyManagers, null, null)
        val server = HttpsServer.create(InetSocketAddress(InetAddress.getByName(LOOPBACK_HOST), 0), 0)
        server.setHttpsConfigurator(HttpsConfigurator(sslContext))
        return server
    }

    private fun serveLoopedBackPayload(
        exchange: HttpExchange,
        serverHandle: LoopbackServerHandle,
    ) {
        val body = serverHandle.respondWithBody
        val declaredLength = serverHandle.declaredContentLength
        try {
            when {
                declaredLength != null -> {
                    exchange.responseHeaders.set("Content-Length", declaredLength.toString())
                    exchange.sendResponseHeaders(200, declaredLength)
                    exchange.responseBody.use { output -> output.write(body) }
                }

                serverHandle.chunkedResponse -> {
                    exchange.sendResponseHeaders(200, 0)
                    exchange.responseBody.use { output -> output.write(body) }
                }

                else -> {
                    exchange.sendResponseHeaders(200, body.size.toLong())
                    exchange.responseBody.use { output -> output.write(body) }
                }
            }
        } catch (_: IOException) {
            // The client may abort mid-stream when the size cap trips; nothing to report.
        }
    }

    private fun serveRedirect(
        exchange: HttpExchange,
        serverHandle: LoopbackServerHandle,
    ) {
        val location =
            when (exchange.requestURI.path) {
                "/redirect-to-metadata" -> "https://169.254.169.254/latest/meta-data/"
                "/redirect-to-plain-http" -> "http://$LOOPBACK_HOST:${serverHandle.port}/data.bin"
                else -> throw java.lang.IllegalStateException("Unexpected redirect path ${exchange.requestURI.path}")
            }
        exchange.responseHeaders.set("Location", location)
        exchange.sendResponseHeaders(302, -1)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Trust store and certificate generation
    // ─────────────────────────────────────────────────────────────────────

    private fun labTrustedSocketPair(trustedCa: X509Certificate): Pair<SSLSocketFactory, X509TrustManager> {
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
        trustStore.load(null, "labtrust".toCharArray())
        trustStore.setCertificateEntry("lab-ca", trustedCa)
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(trustStore)
        val trustManager = trustManagerFactory.trustManagers.filterIsInstance<X509TrustManager>().first()
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManager), null)
        return sslContext.socketFactory to trustManager
    }

    private fun newKeyPair(): KeyPair =
        KeyPairGenerator
            .getInstance("RSA")
            .apply { initialize(2048, SecureRandom()) }
            .generateKeyPair()

    private fun labCertificateMaterial(
        expiredLeaf: Boolean,
        wrongSansLeaf: Boolean,
    ): LabCertificateMaterial {
        val caKeys = newKeyPair()
        val leafKeys = newKeyPair()
        val caCertificate =
            buildCertificate(
                subject = CA_SUBJECT,
                issuer = CA_SUBJECT,
                issuerKey = caKeys.private,
                publicKey = caKeys.public,
                notBefore = Instant.now().minus(Duration.ofHours(1)),
                notAfter = Instant.now().plus(Duration.ofDays(30)),
                subjectAltNames = emptyList(),
                isCertificateAuthority = true,
            )
        val (leafNotBefore, leafNotAfter) =
            if (expiredLeaf) {
                Instant.now().minus(Duration.ofDays(2)) to Instant.now().minus(Duration.ofDays(1))
            } else {
                Instant.now().minus(Duration.ofHours(1)) to Instant.now().plus(Duration.ofDays(30))
            }
        val leafSans =
            if (wrongSansLeaf) {
                listOf(GeneralName(GeneralName.dNSName, DERIA5String(MISMATCH_SAN_HOST)))
            } else {
                listOf(GeneralName(GeneralName.iPAddress, DEROctetString(byteArrayOf(127, 0, 0, 1))))
            }
        val leafCertificate =
            buildCertificate(
                subject = LEAF_SUBJECT,
                issuer = CA_SUBJECT,
                issuerKey = caKeys.private,
                publicKey = leafKeys.public,
                notBefore = leafNotBefore,
                notAfter = leafNotAfter,
                subjectAltNames = leafSans,
                isCertificateAuthority = false,
            )
        return LabCertificateMaterial(caCertificate, leafCertificate, leafKeys.private)
    }

    private fun selfSignedOnlyMaterial(): LabCertificateMaterial {
        val leafKeys = newKeyPair()
        val leafCertificate =
            buildCertificate(
                subject = LEAF_SUBJECT,
                issuer = LEAF_SUBJECT,
                issuerKey = leafKeys.private,
                publicKey = leafKeys.public,
                notBefore = Instant.now().minus(Duration.ofHours(1)),
                notAfter = Instant.now().plus(Duration.ofDays(30)),
                subjectAltNames =
                    listOf(GeneralName(GeneralName.iPAddress, DEROctetString(byteArrayOf(127, 0, 0, 1)))),
                isCertificateAuthority = false,
            )
        return LabCertificateMaterial(null, leafCertificate, leafKeys.private)
    }

    private fun buildCertificate(
        subject: X500Name,
        issuer: X500Name,
        issuerKey: PrivateKey,
        publicKey: PublicKey,
        notBefore: Instant,
        notAfter: Instant,
        subjectAltNames: List<GeneralName>,
        isCertificateAuthority: Boolean,
    ): X509Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.nanoTime()),
                Date.from(notBefore),
                Date.from(notAfter),
                subject,
                SubjectPublicKeyInfo.getInstance(publicKey.encoded),
            )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(isCertificateAuthority))
        builder.addExtension(
            Extension.keyUsage,
            true,
            KeyUsage(
                if (isCertificateAuthority) {
                    KeyUsage.keyCertSign
                } else {
                    KeyUsage.digitalSignature or KeyUsage.keyEncipherment
                },
            ),
        )
        if (!isCertificateAuthority) {
            builder.addExtension(
                Extension.extendedKeyUsage,
                false,
                ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
            )
        }
        if (subjectAltNames.isNotEmpty()) {
            val sans = ASN1EncodableVector()
            subjectAltNames.forEach { sans.add(it) }
            builder.addExtension(Extension.subjectAlternativeName, false, DERSequence(sans))
        }
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }
}
