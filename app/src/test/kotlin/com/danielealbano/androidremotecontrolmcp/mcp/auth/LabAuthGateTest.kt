package com.danielealbano.androidremotecontrolmcp.mcp.auth

import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** Unit tests for the hardened-distribution auth startup gate (H-02). */
class LabAuthGateTest {
    @Test
    fun `hardened build refuses to start with both auth methods disabled`() {
        val exception =
            assertThrows<IllegalStateException> {
                LabAuthGate.validate(
                    hardened = true,
                    bearerTokenEnabled = false,
                    expectedToken = "",
                    oauthEnabled = false,
                )
            }
        assertTrue(exception.message!!.contains("Refuses to start"))
        assertTrue(exception.message!!.contains("OPEN"))
    }

    @Test
    fun `hardened build refuses to start with bearer disabled and oauth-only auth`() {
        val exception =
            assertThrows<IllegalStateException> {
                LabAuthGate.validate(
                    hardened = true,
                    bearerTokenEnabled = false,
                    expectedToken = "",
                    oauthEnabled = true,
                )
            }
        assertTrue(exception.message!!.contains("Refuses to start"))
        assertTrue(exception.message!!.contains("bearer"))
    }

    @Test
    fun `hardened build refuses to start with enabled but blank bearer token`() {
        listOf("", "   ", "\t").forEach { blankToken ->
            val exception =
                assertThrows<IllegalStateException> {
                    LabAuthGate.validate(
                        hardened = true,
                        bearerTokenEnabled = true,
                        expectedToken = blankToken,
                        oauthEnabled = false,
                    )
                }
            assertTrue(exception.message!!.contains("Refuses to start"))
            assertTrue(exception.message!!.contains("bearer token"))
        }
    }

    @Test
    fun `hardened build starts with enforced bearer token only`() {
        assertDoesNotThrow {
            LabAuthGate.validate(
                hardened = true,
                bearerTokenEnabled = true,
                expectedToken = "gateway-to-device-secret",
                oauthEnabled = false,
            )
        }
    }

    @Test
    fun `hardened build starts with enforced bearer token plus oauth`() {
        assertDoesNotThrow {
            LabAuthGate.validate(
                hardened = true,
                bearerTokenEnabled = true,
                expectedToken = "gateway-to-device-secret",
                oauthEnabled = true,
            )
        }
    }

    @Test
    fun `non-hardened build keeps upstream behavior for every configuration`() {
        listOf(
            // bearerTokenEnabled to expectedToken to oauthEnabled; includes the upstream OPEN config.
            Triple(false, "", false),
            Triple(false, "", true),
            Triple(true, "", false),
            Triple(true, "", true),
            Triple(true, "gateway-to-device-secret", false),
            Triple(true, "gateway-to-device-secret", true),
        ).forEach { (bearerTokenEnabled, expectedToken, oauthEnabled) ->
            assertDoesNotThrow {
                LabAuthGate.validate(
                    hardened = false,
                    bearerTokenEnabled = bearerTokenEnabled,
                    expectedToken = expectedToken,
                    oauthEnabled = oauthEnabled,
                )
            }
        }
    }
}
