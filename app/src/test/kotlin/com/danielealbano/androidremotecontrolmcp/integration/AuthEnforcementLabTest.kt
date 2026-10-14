package com.danielealbano.androidremotecontrolmcp.integration

import com.danielealbano.androidremotecontrolmcp.data.model.ServerLogEntry
import com.danielealbano.androidremotecontrolmcp.mcp.RequestOriginPolicy
import com.danielealbano.androidremotecontrolmcp.mcp.installMcpBasePlugins
import com.danielealbano.androidremotecontrolmcp.mcp.installMcpStatelessTransport
import com.danielealbano.androidremotecontrolmcp.services.sharing.EphemeralFileLinkService
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.options
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Integration tests for the hardened lab-distribution auth posture (H-02 / V04 gate):
 * with a production-exact plugin wiring (bearer enforced, OAuth off) every protected
 * endpoint rejects requests without a valid bearer token, token identity is scoped to
 * the device it was issued for, stale tokens are denied after rotation, client-
 * controlled forwarded headers never grant identity, preflight OPTIONS is not failed
 * closed by auth, and OAuth discovery stays intentionally public and scoped.
 */
@DisplayName("Auth Enforcement Lab Tests")
class AuthEnforcementLabTest {
    /**
     * The preflight origin must be centrally approved (H-01 contract: hardened builds deny any
     * cross-origin that is not on the provisioned allowlist, so an unapproved Origin is never
     * answered by CORS) — this constant is the allowlisted browser source for the preflight gate.
     */
    private val approvedPreflightOrigin = "http://localhost:6274"

    @BeforeEach
    fun setUp() {
        McpIntegrationTestHelper.mockAndroidLog()
    }

    @AfterEach
    fun tearDown() {
        McpIntegrationTestHelper.unmockAndroidLog()
    }

    @Test
    fun `unauthorized tool call on mcp is denied before the dispatcher runs`() =
        runTest {
            withHardenedApplication(TOKEN_A) {
                val response =
                    client.post("/mcp") {
                        contentType(ContentType.Application.Json)
                        setBody(toolCallBody())
                    }

                assertEquals(HttpStatusCode.Unauthorized, response.status)
                val body = response.bodyAsText()
                assertTrue(body.contains("unauthorized"))
                assertTrue(body.contains("Authentication required"))
            }
        }

    @Test
    fun `unauthorized event subscription on mcp is denied`() =
        runTest {
            withHardenedApplication(TOKEN_A) {
                val response = client.get("/mcp")

                assertEquals(HttpStatusCode.Unauthorized, response.status)
                assertTrue(response.bodyAsText().contains("unauthorized"))
            }
        }

    @Test
    fun `malformed and wrong credentials are denied`() =
        runTest {
            withHardenedApplication(TOKEN_A) {
                listOf("Basic abc123", "Bearer wrong-token").forEach { authorization ->
                    val response =
                        client.post("/mcp") {
                            header(HttpHeaders.Authorization, authorization)
                            contentType(ContentType.Application.Json)
                            setBody(initializeBody())
                        }

                    assertEquals(HttpStatusCode.Unauthorized, response.status)
                }
            }
        }

    @Test
    fun `health stays public while other protected endpoints require the token`() =
        runTest {
            withHardenedApplication(TOKEN_A) {
                val health = client.get("/health")
                assertEquals(HttpStatusCode.OK, health.status)

                val probeUnauthenticated = client.get("/probe")
                assertEquals(HttpStatusCode.Unauthorized, probeUnauthenticated.status)
                assertTrue(probeUnauthenticated.bodyAsText().contains("unauthorized"))

                val probeAuthorized =
                    client.get("/probe") {
                        header(HttpHeaders.Authorization, "Bearer $TOKEN_A")
                    }
                assertEquals(HttpStatusCode.OK, probeAuthorized.status)
                assertEquals("protected", probeAuthorized.bodyAsText())
            }
        }

    @Test
    fun `token issued for device a is rejected on device b and vice versa`() =
        runTest {
            withHardenedApplication(TOKEN_A) {
                val wrongDevice =
                    client.get("/probe") {
                        header(HttpHeaders.Authorization, "Bearer $TOKEN_B")
                    }
                assertEquals(HttpStatusCode.Unauthorized, wrongDevice.status)

                val ownDevice =
                    client.get("/probe") {
                        header(HttpHeaders.Authorization, "Bearer $TOKEN_A")
                    }
                assertEquals(HttpStatusCode.OK, ownDevice.status)
            }
            withHardenedApplication(TOKEN_B) {
                val wrongDevice =
                    client.get("/probe") {
                        header(HttpHeaders.Authorization, "Bearer $TOKEN_A")
                    }
                assertEquals(HttpStatusCode.Unauthorized, wrongDevice.status)
            }
        }

    @Test
    fun `stale token is denied after token rotation`() =
        runTest {
            withHardenedApplication(TOKEN_OLD) {
                val current =
                    client.get("/probe") {
                        header(HttpHeaders.Authorization, "Bearer $TOKEN_OLD")
                    }
                assertEquals(HttpStatusCode.OK, current.status)
            }
            withHardenedApplication(TOKEN_NEW) {
                val stale =
                    client.get("/probe") {
                        header(HttpHeaders.Authorization, "Bearer $TOKEN_OLD")
                    }
                assertEquals(HttpStatusCode.Unauthorized, stale.status)

                val rotated =
                    client.get("/probe") {
                        header(HttpHeaders.Authorization, "Bearer $TOKEN_NEW")
                    }
                assertEquals(HttpStatusCode.OK, rotated.status)
            }
        }

    @Test
    fun `client-controlled forwarded headers cannot grant trusted identity`() =
        runTest {
            withHardenedApplication(TOKEN_A) { deps ->
                listOf(
                    client.get("/probe") {
                        header("X-Forwarded-For", "10.0.0.1")
                        header("X-Forwarded-Host", "gateway.example.com")
                    },
                    client.post("/mcp") {
                        header("X-Forwarded-For", "10.0.0.1")
                        header("X-Forwarded-Host", "gateway.example.com")
                        contentType(ContentType.Application.Json)
                        setBody(initializeBody())
                    },
                ).forEach { response ->
                    assertEquals(HttpStatusCode.Unauthorized, response.status)
                    assertTrue(response.bodyAsText().contains("unauthorized"))
                }

                // Identity was not granted; the fail-closed branch still recorded the failure.
                assertTrue(deps.serverLog.entries.any { it.type == ServerLogEntry.Type.AUTH })
            }
        }

    @Test
    fun `preflight options is answered by cors instead of being failed closed by auth`() =
        runTest {
            withHardenedApplication(TOKEN_A) {
                val preflight =
                    client.options("/mcp") {
                        header(HttpHeaders.Origin, approvedPreflightOrigin)
                        header(HttpHeaders.AccessControlRequestMethod, "POST")
                    }

                assertNotEquals(HttpStatusCode.Unauthorized, preflight.status)
                assertNotNull(preflight.headers["Access-Control-Allow-Origin"])

                // Preflight exemption must not weaken enforcement of real requests.
                val unauthenticated =
                    client.post("/mcp") {
                        contentType(ContentType.Application.Json)
                        setBody(initializeBody())
                    }
                assertEquals(HttpStatusCode.Unauthorized, unauthenticated.status)
            }
        }

    @Test
    fun `oauth discovery stays public and scoped while mcp stays protected`() =
        runTest {
            McpIntegrationTestHelper.withOAuthTestApplication(
                bearerTokenEnabled = true,
                bearerToken = TOKEN_A,
            ) { context ->
                val discovery = context.httpClient.get("/.well-known/oauth-protected-resource/mcp")
                assertEquals(HttpStatusCode.OK, discovery.status)

                val unauthenticated =
                    context.httpClient.post("/mcp") {
                        contentType(ContentType.Application.Json)
                        setBody(initializeBody())
                    }
                assertEquals(HttpStatusCode.Unauthorized, unauthenticated.status)

                val wwwAuthenticate = unauthenticated.headers["WWW-Authenticate"]
                assertNotNull(wwwAuthenticate)
                assertTrue(wwwAuthenticate!!.contains("resource_metadata"))
            }
        }

    /**
     * Runs the test with production-exact McpServer auth wiring in the hardened posture:
     * bearer auth enforced (OAuth off) and the production exclusions, so requests behave
     * exactly as against the real server.
     */
    private suspend fun withHardenedApplication(
        expectedToken: String,
        testBlock: suspend ApplicationTestBuilder.(MockDependencies) -> Unit,
    ) {
        val deps = McpIntegrationTestHelper.createMockDependencies()
        val sdkServer = McpIntegrationTestHelper.createSdkServer(deps)
        testApplication {
            application {
                installMcpBasePlugins(
                    configureOriginPolicy = {
                        policy =
                            RequestOriginPolicy.create(
                                isLabHardened = true,
                                approvedOrigins = setOf(approvedPreflightOrigin),
                            )
                    },
                ) {
                    bearerTokenEnabled = true
                    this.expectedToken = expectedToken
                    oauthEnabled = false
                    excludedPaths = setOf("/health", "/register", "/token", "/authorize", "/authorize/status")
                    excludedPathPrefixes = setOf(EphemeralFileLinkService.PATH_PREFIX, "/.well-known/")
                    onAuthFailure = { deps.serverLog.log(ServerLogEntry.Type.AUTH, "Authentication failed from $it") }
                }
                routing {
                    get("/health") { call.respondText("/health is public") }
                    get("/probe") { call.respondText("protected") }
                }
                installMcpStatelessTransport { sdkServer }
            }
            testBlock(deps)
        }
    }

    private fun initializeBody(): String =
        Json.encodeToString(
            JsonObject.serializer(),
            buildJsonObject {
                put("jsonrpc", "2.0")
                put("id", 1)
                put("method", "initialize")
            },
        )

    private fun toolCallBody(): String =
        Json.encodeToString(
            JsonObject.serializer(),
            buildJsonObject {
                put("jsonrpc", "2.0")
                put("id", 2)
                put("method", "tools/call")
                put(
                    "params",
                    buildJsonObject {
                        put("name", "device_status")
                        put("args", buildJsonObject { })
                    },
                )
            },
        )

    private companion object {
        const val TOKEN_A = "device-a-token"
        const val TOKEN_B = "device-b-token"
        const val TOKEN_OLD = "rotated-old-token"
        const val TOKEN_NEW = "rotated-new-token"
    }
}
