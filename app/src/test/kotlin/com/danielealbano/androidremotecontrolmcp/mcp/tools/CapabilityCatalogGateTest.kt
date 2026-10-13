package com.danielealbano.androidremotecontrolmcp.mcp.tools

import com.danielealbano.androidremotecontrolmcp.data.model.ServerLogEntry
import com.danielealbano.androidremotecontrolmcp.testutil.RecordingServerLogRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("CapabilityCatalogGate and registrar dispatch integration")
class CapabilityCatalogGateTest {
    private val request = mockk<CallToolRequest>()

    private val connection = mockk<ClientConnection>(relaxed = true)

    private val schema = mockk<ToolSchema>()

    private fun smallCatalog(): CapabilityCatalog =
        CapabilityCatalog.of(
            listOf(
                CapabilityEntry(
                    toolName = "tap",
                    apiId = "android.ui.tap.v1",
                    adapterId = "action_executor_v1",
                    privilegeTier = PrivilegeTier.T2_TEST,
                    risk = CapabilityRisk.MUTATING,
                ),
                CapabilityEntry(
                    toolName = "managed_probe",
                    apiId = "android.probe.managed.v1",
                    adapterId = "action_executor_v1",
                    privilegeTier = PrivilegeTier.T3_MANAGED,
                    risk = CapabilityRisk.MUTATING,
                ),
            ),
        )

    @Test
    fun `inactive gate allows every dispatch without catalog evidence`() {
        val verdict = CapabilityCatalogGate.INACTIVE.evaluate("not_a_real_tool")
        assertInstanceOf(CapabilityVerdict.Allowed::class.java, verdict)
        val allowed = verdict as CapabilityVerdict.Allowed
        assertEquals(null, allowed.entry)
    }

    @Test
    fun `enforcing gate rejects unknown tools with typed NOT_IN_CATALOG`() {
        val gate = CapabilityCatalogGate.enforcing(smallCatalog())

        val verdict = gate.evaluate("not_a_real_tool")

        assertInstanceOf(CapabilityVerdict.Denied::class.java, verdict)
        val denied = verdict as CapabilityVerdict.Denied
        assertEquals(CatalogDenialReason.NOT_IN_CATALOG, denied.reason)
        assertTrue(denied.detail.contains("not_a_real_tool"))
        assertTrue(denied.detail.contains("capability catalog"))
    }

    @Test
    fun `enforcing gate admits catalog-listed tools with the catalog entry`() {
        val verdict = CapabilityCatalogGate.enforcing(smallCatalog()).evaluate("tap")
        val allowed = assertInstanceOf(CapabilityVerdict.Allowed::class.java, verdict)
        assertEquals("android.ui.tap.v1", allowed.entry?.apiId)
        assertEquals(PrivilegeTier.T2_TEST, allowed.entry?.privilegeTier)
    }

    @Test
    fun `registry integrity reports drift in both directions`() {
        val catalog = smallCatalog()

        val bothWays = catalog.checkRegisteredToolNames(listOf("tap", "mystery_tool"))
        assertEquals(setOf("mystery_tool"), bothWays.missingCatalogEntries)
        assertEquals(setOf("managed_probe"), bothWays.unregisteredCatalogEntries)
        assertFalse(bothWays.intact)
    }

    @Test
    fun `catalog-denied dispatch never reaches the handler and logs once`() =
        runTest {
            val recorder = RecordingServerLogRepository()
            var handlerInvocations = 0
            val handlerSlot = slot<suspend ClientConnection.(CallToolRequest) -> CallToolResult>()
            val server = mockk<Server>(relaxed = true)
            every {
                server.addTool(
                    name = any(),
                    description = any(),
                    inputSchema = any(),
                    handler = capture(handlerSlot),
                )
            } returns Unit

            val registrar =
                LoggedToolRegistrar(
                    server,
                    recorder,
                    capabilityGate = CapabilityCatalogGate.enforcing(smallCatalog()),
                )
            registrar.addTool(
                "not_a_real_tool",
                "android_not_a_real_tool",
                "not listed in the catalog",
                schema,
            ) {
                handlerInvocations += 1
                CallToolResult(content = listOf(TextContent(text = "reached")))
            }
            val dispatch = handlerSlot.captured
            val result = dispatch(connection, request)

            assertTrue(result.isError == true)
            assertEquals(1, result.content.size)
            assertTrue((result.content[0] as TextContent).text.contains("not listed in the capability catalog"))
            assertEquals(0, handlerInvocations)
            val logEntry = recorder.ofType(ServerLogEntry.Type.TOOL_CALL).single()
            assertEquals("catalog_denied", logEntry.message)
            assertEquals("not_a_real_tool", logEntry.toolName)
            assertEquals(0L, logEntry.durationMs)
        }

    @Test
    fun `allowed dispatch passes through to the underlying handler chain`() =
        runTest {
            val recorder = RecordingServerLogRepository()
            val handlerSlot = slot<suspend ClientConnection.(CallToolRequest) -> CallToolResult>()
            val server = mockk<Server>(relaxed = true)
            every {
                server.addTool(
                    name = any(),
                    description = any(),
                    inputSchema = any(),
                    handler = capture(handlerSlot),
                )
            } returns Unit

            val registrar =
                LoggedToolRegistrar(
                    server,
                    recorder,
                    capabilityGate = CapabilityCatalogGate.enforcing(smallCatalog()),
                )
            registrar.addTool(
                "tap",
                "android_tap",
                "catalog-listed tool",
                schema,
            ) { CallToolResult(content = listOf(TextContent(text = "ok"))) }
            val dispatch = handlerSlot.captured
            val result = dispatch(connection, request)

            assertFalse(result.isError == true)
            assertEquals("ok", (result.content[0] as TextContent).text)
            val logEntries = recorder.ofType(ServerLogEntry.Type.TOOL_CALL)
            assertEquals(1, logEntries.size)
            assertEquals("", logEntries.single().message)
            assertEquals("tap", logEntries.single().toolName)
        }

    @Test
    fun `registrar records every registered tool name for integrity checks`() {
        val server = mockk<Server>(relaxed = true)
        val registrar = LoggedToolRegistrar(server, RecordingServerLogRepository())
        registrar.addTool("tap", "android_tap", "one", schema) {
            CallToolResult(content = listOf(TextContent(text = "ok")))
        }
        registrar.addTool("swipe", "android_swipe", "two", schema) {
            CallToolResult(content = listOf(TextContent(text = "ok")))
        }

        assertEquals(setOf("tap", "swipe"), registrar.registeredToolNames())
    }
}
