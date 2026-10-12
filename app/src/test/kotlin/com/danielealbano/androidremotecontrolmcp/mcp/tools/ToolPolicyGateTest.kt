package com.danielealbano.androidremotecontrolmcp.mcp.tools

import com.danielealbano.androidremotecontrolmcp.data.model.ToolPermissionsConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.IOException

@DisplayName("ToolPolicyGate")
class ToolPolicyGateTest {
    @Test
    fun `allows delegates to the live policy`() =
        runTest {
            val gate = ToolPolicyGate { ToolPermissionsConfig() }
            assertTrue(gate.allows("tap"))
        }

    @Test
    fun `denies when the live policy denies`() =
        runTest {
            val gate = ToolPolicyGate { ToolPermissionsConfig.DENY_ALL }
            assertFalse(gate.allows("tap"))
        }

    @Test
    fun `denies fail closed when the policy store cannot be read`() =
        runTest {
            val gate = ToolPolicyGate { throw IOException("policy store unavailable") }
            assertFalse(gate.allows("tap"))
        }

    @Test
    fun `rethrows cancellation instead of denying`() =
        runTest {
            val gate = ToolPolicyGate { throw CancellationException("cancelled") }
            assertThrows<CancellationException> { gate.allows("tap") }
        }

    @Test
    fun `INACTIVE gate allows every tool`() =
        runTest {
            assertTrue(ToolPolicyGate.INACTIVE.allows("tap"))
            assertTrue(ToolPolicyGate.INACTIVE.allows("get_screen_state"))
        }
}
