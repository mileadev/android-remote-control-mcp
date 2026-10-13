package com.danielealbano.androidremotecontrolmcp.integration

import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.testutil.ExpectedToolSurface
import io.mockk.coEvery
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("MCP Protocol Integration Tests")
class McpProtocolIntegrationTest {
    @BeforeEach
    fun setUp() {
        McpIntegrationTestHelper.mockAndroidLog()
    }

    @AfterEach
    fun tearDown() {
        McpIntegrationTestHelper.unmockAndroidLog()
    }

    @Test
    fun `client connects successfully and completes initialize handshake`() =
        runTest {
            McpIntegrationTestHelper.withTestApplication { client, _ ->
                // If connect() succeeds, the initialize handshake completed
                assertNotNull(client.serverCapabilities)
                assertNotNull(client.serverVersion)
                assertEquals("android-remote-control-mcp", client.serverVersion?.name) // No slug in default tests
            }
        }

    @Test
    fun `listTools returns exactly the registered tool surface`() =
        runTest {
            McpIntegrationTestHelper.withTestApplication { client, _ ->
                val result = client.listTools()
                val expected = ExpectedToolSurface.prefixedToolNames()
                val actual = result.tools.map { it.name }.toSet()
                assertEquals(
                    EXPECTED_TOOL_SURFACE_SIZE,
                    expected.size,
                    "the catalog lists an unexpected number of tools for this flavour: " +
                        "catalog=${expected.sorted()}",
                )
                assertEquals(
                    expected.size,
                    result.tools.size,
                    "live tool count drifted from the catalog: missing=${expected - actual}, " +
                        "not catalogued=${actual - expected}",
                )
            }
        }

    @Test
    fun `listTools includes correct tool metadata for each tool`() =
        runTest {
            McpIntegrationTestHelper.withTestApplication { client, _ ->
                val result = client.listTools()

                result.tools.forEach { tool ->
                    assertNotNull(tool.name, "Tool missing name")
                    assertNotNull(tool.description, "Tool ${tool.name} missing description")
                    assertNotNull(tool.inputSchema, "Tool ${tool.name} missing inputSchema")
                }
            }
        }

    @Test
    fun `server capabilities include tools`() =
        runTest {
            McpIntegrationTestHelper.withTestApplication { client, _ ->
                assertNotNull(client.serverCapabilities?.tools)
            }
        }

    @Test
    fun `listTools contains expected tool names`() =
        runTest {
            McpIntegrationTestHelper.withTestApplication { client, _ ->
                val result = client.listTools()
                val toolNames = result.tools.map { it.name }.toSet()

                assertEquals(
                    ExpectedToolSurface.prefixedToolNames(),
                    toolNames,
                    "the live tool surface differs from the catalog-derived one: " +
                        "missing=${ExpectedToolSurface.prefixedToolNames() - toolNames}, " +
                        "not catalogued=${toolNames - ExpectedToolSurface.prefixedToolNames()}",
                )
            }
        }

    @Test
    fun `listTools with device slug includes slug in tool names`() =
        runTest {
            McpIntegrationTestHelper.withTestApplication(
                deviceSlug = "pixel7",
            ) { client, _ ->
                val result = client.listTools()
                result.tools.forEach { tool ->
                    assertTrue(
                        tool.name.startsWith("android_pixel7_"),
                        "Tool '${tool.name}' should start with 'android_pixel7_'",
                    )
                }
            }
        }

    @Test
    fun `server name includes device slug when set`() =
        runTest {
            McpIntegrationTestHelper.withTestApplication(
                deviceSlug = "pixel7",
            ) { client, _ ->
                assertEquals("android-remote-control-mcp-pixel7", client.serverVersion?.name)
            }
        }

    @Test
    fun `server name without slug uses default`() =
        runTest {
            McpIntegrationTestHelper.withTestApplication { client, _ ->
                assertEquals("android-remote-control-mcp", client.serverVersion?.name)
            }
        }

    @Test
    fun `tool with slug can be called successfully`() =
        runTest {
            val deps = McpIntegrationTestHelper.createMockDependencies()
            coEvery { deps.actionExecutor.tap(any(), any()) } returns Result.success(Unit)

            McpIntegrationTestHelper.withTestApplication(
                deps = deps,
                deviceSlug = "pixel7",
            ) { client, _ ->
                val result =
                    client.callTool(
                        name = "android_pixel7_tap",
                        arguments = mapOf("x" to 100, "y" to 200),
                    )
                assertNotEquals(true, result.isError)
            }
        }

    private companion object {
        /**
         * The one literal pin on the size of the surface. Every other assertion on the surface
         * compares the live registration against the catalog, so a tool deleted from both the
         * catalog and its registration helper would leave them green while the tool vanishes.
         * `labHardened` drops `android_download_from_url`.
         */
        private val EXPECTED_TOOL_SURFACE_SIZE = if (BuildConfig.LAB_HARDENED) 56 else 57
    }
}
