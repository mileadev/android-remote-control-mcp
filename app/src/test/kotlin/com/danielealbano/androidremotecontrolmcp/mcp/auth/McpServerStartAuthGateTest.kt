package com.danielealbano.androidremotecontrolmcp.mcp.auth

import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.data.model.BindingAddress
import com.danielealbano.androidremotecontrolmcp.data.model.ServerConfig
import com.danielealbano.androidremotecontrolmcp.integration.McpIntegrationTestHelper
import com.danielealbano.androidremotecontrolmcp.mcp.McpServer
import com.danielealbano.androidremotecontrolmcp.mcp.oauth.AuthorizationCodeStore
import com.danielealbano.androidremotecontrolmcp.mcp.oauth.JwtTokenService
import com.danielealbano.androidremotecontrolmcp.mcp.oauth.OAuthApprovalCoordinator
import com.danielealbano.androidremotecontrolmcp.mcp.oauth.OAuthServerDeps
import com.danielealbano.androidremotecontrolmcp.services.sharing.EphemeralFileLinkService
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.ServerSocket

/**
 * Unit tests proving [McpServer.start] consults [LabAuthGate] with the distribution's
 * hardened flag: in `labHardened` the start path refuses OPEN / token-less auth
 * configurations before binding any socket; gms/foss keep upstream behavior.
 */
class McpServerStartAuthGateTest {
    private companion object {
        const val VALID_TOKEN = "start-gate-test-token"
    }

    @Test
    fun `hardened server refuses to start with both auth methods disabled`() {
        assumeTrue(BuildConfig.LAB_HARDENED)
        val server = testMcpServer(testConfig(bearerTokenEnabled = false, oauthEnabled = false))

        val exception = assertThrows<IllegalStateException> { server.start() }
        assertTrue(exception.message!!.contains("Refuses to start"))
        assertFalse(server.isRunning())
    }

    @Test
    fun `hardened server refuses to start with enabled but blank bearer token`() {
        assumeTrue(BuildConfig.LAB_HARDENED)
        val server =
            testMcpServer(
                ServerConfig(
                    port = freePort(),
                    bindingAddress = BindingAddress.LOCALHOST,
                    bearerToken = "",
                    bearerTokenEnabled = true,
                    oauthEnabled = false,
                ),
            )

        val exception = assertThrows<IllegalStateException> { server.start() }
        assertTrue(exception.message!!.contains("Refuses to start"))
        assertFalse(server.isRunning())
    }

    @Test
    fun `hardened server starts with enforced bearer token`() {
        assumeTrue(BuildConfig.LAB_HARDENED)
        val server = testMcpServer(testConfig(bearerTokenEnabled = true, oauthEnabled = false))

        assertDoesNotThrow { server.start() }
        assertTrue(server.isRunning())
        assertDoesNotThrow { server.stop() }
        assertFalse(server.isRunning())
    }

    @Test
    fun `non-hardened server keeps upstream behavior and allows dual-off auth`() {
        assumeFalse(BuildConfig.LAB_HARDENED)
        val server = testMcpServer(testConfig(bearerTokenEnabled = false, oauthEnabled = false))

        assertDoesNotThrow { server.start() }
        assertTrue(server.isRunning())
        assertDoesNotThrow { server.stop() }
        assertFalse(server.isRunning())
    }

    private fun testConfig(
        bearerTokenEnabled: Boolean,
        oauthEnabled: Boolean,
    ): ServerConfig =
        ServerConfig(
            port = freePort(),
            bindingAddress = BindingAddress.LOCALHOST,
            bearerToken = if (bearerTokenEnabled) VALID_TOKEN else "",
            bearerTokenEnabled = bearerTokenEnabled,
            oauthEnabled = oauthEnabled,
        )

    private fun testMcpServer(config: ServerConfig): McpServer {
        val deps = McpIntegrationTestHelper.createMockDependencies()
        val oauth =
            OAuthServerDeps(
                jwtTokenService = mockk<JwtTokenService>(relaxed = true),
                oauthClientRepository = mockk(relaxed = true),
                authorizationCodeStore = mockk<AuthorizationCodeStore>(relaxed = true),
                approvalCoordinator = mockk<OAuthApprovalCoordinator>(relaxed = true),
                geoIpResolver = { null },
            )
        return McpServer(
            config = config,
            httpsMaterial = null,
            mcpSdkServer = McpIntegrationTestHelper.createSdkServer(deps),
            ephemeralFileLinkService = mockk<EphemeralFileLinkService>(relaxed = true),
            oauth = oauth,
            serverLog = deps.serverLog,
        )
    }

    private fun freePort(): Int = ServerSocket(0).use { socket -> socket.localPort }
}
