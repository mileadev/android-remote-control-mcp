package com.danielealbano.androidremotecontrolmcp.integration

import com.danielealbano.androidremotecontrolmcp.mcp.RequestOriginPolicy
import com.danielealbano.androidremotecontrolmcp.mcp.effectiveBaseUrl
import com.danielealbano.androidremotecontrolmcp.mcp.installMcpBasePlugins
import com.danielealbano.androidremotecontrolmcp.mcp.installMcpStatelessTransport
import com.danielealbano.androidremotecontrolmcp.services.sharing.EphemeralFileLinkService
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.options
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.response.respondText
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * Hardened-flavor Origin/Host enforcement acceptance tests (handoff item H-01, V-gate V03):
 * the origin policy, CORS and bearer auth are wired through the REAL [installMcpBasePlugins]
 * pipeline in hardened mode (`RequestOriginPolicy.create(isLabHardened = true, ...)`) with a
 * single approved cross-origin allowlist entry, verifying that:
 *  - cross-origin/cross-host requests are denied 403 before any handler executes,
 *  - denied responses never reach the route handler (fail closed),
 *  - an absent Origin still requires a valid bearer token (CORS-before-auth, fail closed),
 *  - an approved origin is reflected exactly and still cannot bypass auth.
 */
@DisplayName("Origin/Host enforcement (hardened lab build)")
class AuthAndOriginLabTest {
    private val approvedOrigin = "https://station.lab.example"
    private val evilOrigin = "https://evil.example"
    private lateinit var probeHits: AtomicInteger

    @BeforeEach
    fun setUp() {
        McpIntegrationTestHelper.mockAndroidLog()
        probeHits = AtomicInteger(0)
    }

    @AfterEach
    fun tearDown() {
        McpIntegrationTestHelper.unmockAndroidLog()
    }

    /**
     * Configures the production plugin pipeline with a HARDENED origin policy (empty-host fallback
     * is the server's own local address; the only approved cross-origin is [approvedOrigin]) plus
     * bearer-token auth identical to production, and a `/probe` handler that counts every execution
     * so denial paths can prove the handler never ran.
     */
    private suspend fun withHardenedOriginApp(testBlock: suspend ApplicationTestBuilder.() -> Unit) {
        val deps = McpIntegrationTestHelper.createMockDependencies()
        val sdkServer = McpIntegrationTestHelper.createSdkServer(deps)
        testApplication {
            application {
                installMcpBasePlugins(
                    configureOriginPolicy = {
                        policy =
                            RequestOriginPolicy.create(
                                isLabHardened = true,
                                approvedOrigins = setOf(approvedOrigin),
                            )
                    },
                ) {
                    bearerTokenEnabled = true
                    expectedToken = McpIntegrationTestHelper.TEST_BEARER_TOKEN
                    this.oauthEnabled = false
                    baseUrlOf = { effectiveBaseUrl(it, "") }
                    excludedPaths = setOf("/health", "/register", "/token", "/authorize", "/authorize/status")
                    excludedPathPrefixes = setOf(EphemeralFileLinkService.PATH_PREFIX, "/.well-known/")
                }
                routing {
                    get("/probe") {
                        probeHits.incrementAndGet()
                        call.respondText("probe-get", ContentType.Application.Json)
                    }
                    post("/probe") {
                        probeHits.incrementAndGet()
                        call.respondText("probe-post", ContentType.Application.Json)
                    }
                    delete("/probe") {
                        probeHits.incrementAndGet()
                        call.respondText("probe-delete", ContentType.Application.Json)
                    }
                }
                installMcpStatelessTransport { sdkServer }
            }
            testBlock()
        }
    }

    private fun HttpResponse.allowOrigin(): String? = headers[HttpHeaders.AccessControlAllowOrigin]

    private fun HttpResponse.headerTokens(name: String): List<String> =
        headers[name]
            .orEmpty()
            .split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }

    @Test
    fun rejectsCrossOriginGetPostDeleteOptions() =
        runTest {
            withHardenedOriginApp {
                val forbiddenBodies = mutableListOf<String>()

                val postProbe = client.post("/probe") { header(HttpHeaders.Origin, evilOrigin) }
                assertEquals(HttpStatusCode.Forbidden, postProbe.status, "POST /probe from evil Origin")
                forbiddenBodies += postProbe.bodyAsText()

                val getProbe = client.get("/probe") { header(HttpHeaders.Origin, evilOrigin) }
                assertEquals(HttpStatusCode.Forbidden, getProbe.status, "GET /probe from evil Origin")
                forbiddenBodies += getProbe.bodyAsText()

                val deleteProbe = client.delete("/probe") { header(HttpHeaders.Origin, evilOrigin) }
                assertEquals(HttpStatusCode.Forbidden, deleteProbe.status, "DELETE /probe from evil Origin")
                forbiddenBodies += deleteProbe.bodyAsText()

                val preflight =
                    client.options("/probe") {
                        header(HttpHeaders.Origin, evilOrigin)
                        header(HttpHeaders.AccessControlRequestMethod, "POST")
                    }
                assertEquals(HttpStatusCode.Forbidden, preflight.status, "evil preflight")
                forbiddenBodies += preflight.bodyAsText()

                forbiddenBodies.forEach { body ->
                    assertTrue("origin_not_allowed" in body, "expected origin_not_allowed in body '$body'")
                }
                assertEquals(0, probeHits.get(), "handlers must never execute on denial")
            }
        }

    @Test
    fun rejectsDnsRebindingHostAndNullOrigin() =
        runTest {
            withHardenedOriginApp {
                val rebound =
                    client.get("/probe") {
                        header(HttpHeaders.Host, "attacker.rebind.example")
                    }
                assertEquals(HttpStatusCode.Forbidden, rebound.status, "rebound Host must be rejected")
                assertTrue("origin_not_allowed" in rebound.bodyAsText(), "rebound Host denial body")

                val nullOrigin =
                    client.get("/probe") {
                        header(HttpHeaders.Origin, "null")
                    }
                assertEquals(HttpStatusCode.Forbidden, nullOrigin.status, "Origin 'null' must be rejected")

                val emptyOrigin =
                    client.get("/probe") {
                        header(HttpHeaders.Origin, "*")
                    }
                assertEquals(HttpStatusCode.Forbidden, emptyOrigin.status, "Origin '*' must be rejected")

                assertTrue(probeHits.get() == 0, "handlers must never execute on denial")
            }
        }

    @Test
    fun acceptsAbsentOriginOnlyWithValidBearer() =
        runTest {
            withHardenedOriginApp {
                val unauthenticated =
                    client.post("/mcp") {
                        contentType(ContentType.Application.Json)
                        setBody("""{"jsonrpc":"2.0","id":1,"method":"initialize"}""")
                    }
                assertEquals(
                    HttpStatusCode.Unauthorized,
                    unauthenticated.status,
                    "non-origin (native client) request must still fail closed on missing auth",
                )

                val authenticated =
                    client.post("/mcp") {
                        header(HttpHeaders.Authorization, "Bearer ${McpIntegrationTestHelper.TEST_BEARER_TOKEN}")
                        header(HttpHeaders.Accept, "application/json, text/event-stream")
                        contentType(ContentType.Application.Json)
                        setBody(
                            """{"jsonrpc":"2.0","id":1,"method":"initialize",""" +
                                """"params":{"protocolVersion":"2025-06-18","capabilities":{},""" +
                                """"clientInfo":{"name":"origin-lab-test","version":"1.0"}}}""",
                        )
                    }
                assertTrue(
                    authenticated.status.value in 200..299,
                    "native (no Origin) request with valid bearer must succeed, was ${authenticated.status}",
                )
                assertTrue(probeHits.get() == 0, "/probe was not involved on the /mcp paths")
            }
        }

    @Test
    fun doesNotExecuteHandlerOnDenial() =
        runTest {
            withHardenedOriginApp {
                val response = client.get("/probe") { header(HttpHeaders.Origin, evilOrigin) }
                val denialBody = response.bodyAsText()
                assertEquals(HttpStatusCode.Forbidden, response.status)
                assertTrue(
                    "origin_not_allowed" in denialBody,
                    "expected origin_not_allowed body, was '$denialBody'",
                )
                assertEquals(0, probeHits.get(), "a denied request must never reach the route handler")
            }
        }

    @Test
    fun approvedOriginPreflightIsReflectedAndSafe() =
        runTest {
            withHardenedOriginApp {
                val preflight =
                    client.options("/probe") {
                        header(HttpHeaders.Origin, approvedOrigin)
                        header(HttpHeaders.AccessControlRequestMethod, "DELETE")
                        header(HttpHeaders.AccessControlRequestHeaders, "authorization, content-type")
                    }
                assertTrue(
                    preflight.status.value in 200..299,
                    "approved-origin preflight must succeed, was ${preflight.status}",
                )
                assertEquals(approvedOrigin, preflight.allowOrigin(), "ACAO must reflect the exact approved origin")
                val allowedMethods = preflight.headerTokens(HttpHeaders.AccessControlAllowMethods)
                assertTrue("DELETE" in allowedMethods, "expected DELETE in Allow-Methods, was $allowedMethods")
                val allowedHeaders =
                    preflight.headerTokens(HttpHeaders.AccessControlAllowHeaders).map { it.lowercase() }
                listOf("authorization", "content-type", "mcp-protocol-version", "mcp-session-id").forEach {
                    assertTrue(it in allowedHeaders, "expected '$it' in Allow-Headers, was $allowedHeaders")
                }
            }
        }

    @Test
    fun approvedOriginStillRequiresBearerToken() =
        runTest {
            withHardenedOriginApp {
                val unauthenticated = client.get("/probe") { header(HttpHeaders.Origin, approvedOrigin) }
                assertEquals(
                    HttpStatusCode.Unauthorized,
                    unauthenticated.status,
                    "an approved Origin must NOT bypass bearer auth",
                )
                assertEquals(approvedOrigin, unauthenticated.allowOrigin())

                val authenticated =
                    client.get("/probe") {
                        header(HttpHeaders.Origin, approvedOrigin)
                        header(HttpHeaders.Authorization, "Bearer ${McpIntegrationTestHelper.TEST_BEARER_TOKEN}")
                    }
                assertTrue(
                    authenticated.status.value in 200..299,
                    "approved Origin + valid bearer must reach the handler, was ${authenticated.status}",
                )
                assertEquals(1, probeHits.get(), "exactly one approved + authenticated request executed")
            }
        }

    @Test
    fun validBearerDoesNotExcuseInvalidOrigin() =
        runTest {
            withHardenedOriginApp {
                val response =
                    client.post("/mcp") {
                        header(HttpHeaders.Origin, evilOrigin)
                        header(HttpHeaders.Authorization, "Bearer ${McpIntegrationTestHelper.TEST_BEARER_TOKEN}")
                        header(HttpHeaders.Accept, "application/json, text/event-stream")
                        contentType(ContentType.Application.Json)
                        setBody(
                            """{"jsonrpc":"2.0","id":1,"method":"initialize",""" +
                                """"params":{"protocolVersion":"2025-06-18","capabilities":{},""" +
                                """"clientInfo":{"name":"origin-lab-test","version":"1.0"}}}""",
                        )
                    }
                assertEquals(
                    HttpStatusCode.Forbidden,
                    response.status,
                    "a valid bearer token must not excuse a forbidden Origin",
                )
                val denialBody = response.bodyAsText()
                assertTrue(
                    "origin_not_allowed" in denialBody,
                    "expected origin_not_allowed body, was '$denialBody'",
                )
            }
        }
}
