package com.danielealbano.androidremotecontrolmcp.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("privilege tier ceiling gating")
class PrivilegeTierGatingTest {
    private fun entryAtTier(
        toolName: String,
        tier: PrivilegeTier,
    ): CapabilityEntry =
        CapabilityEntry(
            toolName = toolName,
            apiId = "android.probe.$toolName.v1",
            adapterId = "probe_adapter_v1",
            privilegeTier = tier,
            risk = CapabilityRisk.MUTATING,
        )

    private fun catalogWith(vararg entries: CapabilityEntry): CapabilityCatalog = CapabilityCatalog.of(entries.toList())

    private fun deniedReason(verdict: CapabilityVerdict): CatalogDenialReason =
        when (verdict) {
            is CapabilityVerdict.Denied -> verdict.reason
            is CapabilityVerdict.Allowed -> error("expected denial, got allowed: $verdict")
        }

    @Test
    fun `tiers are ranked lowest to highest risk`() {
        assertEquals(1, PrivilegeTier.T1_APP.rank)
        assertEquals(2, PrivilegeTier.T2_TEST.rank)
        assertEquals(3, PrivilegeTier.T3_MANAGED.rank)
        assertEquals(4, PrivilegeTier.T4_USERDEBUG.rank)
        assertEquals(5, PrivilegeTier.T5_PLATFORM.rank)
    }

    @Test
    fun `default ceiling admits app and test tiers only`() {
        val gate =
            CapabilityCatalogGate.enforcing(
                catalogWith(
                    entryAtTier("app_probe", PrivilegeTier.T1_APP),
                    entryAtTier("test_probe", PrivilegeTier.T2_TEST),
                    entryAtTier("managed_probe", PrivilegeTier.T3_MANAGED),
                    entryAtTier("userdebug_probe", PrivilegeTier.T4_USERDEBUG),
                    entryAtTier("platform_probe", PrivilegeTier.T5_PLATFORM),
                ),
            )

        listOf("app_probe", "test_probe").forEach { toolName ->
            assertInstanceOf(CapabilityVerdict.Allowed::class.java, gate.evaluate(toolName))
        }
        listOf(
            "managed_probe" to CatalogDenialReason.TIER_NOT_PROVISIONED,
            "userdebug_probe" to CatalogDenialReason.TIER_NOT_PROVISIONED,
            "platform_probe" to CatalogDenialReason.TIER_NOT_PROVISIONED,
        ).forEach { (toolName, reason) -> assertEquals(reason, deniedReason(gate.evaluate(toolName))) }
    }

    @Test
    fun `hardened default keeps managed-grade tiers off unless provisioned`() {
        // This test IS the T3-off-by-default acceptance check: DEFAULT_PROVISIONED_TIER is
        // T2_TEST, so an implicitly enforced catalog never admits T3_MANAGED and above.
        assertEquals(PrivilegeTier.T2_TEST, CapabilityCatalogGate.DEFAULT_PROVISIONED_TIER)
        val entry = entryAtTier("managed_probe", PrivilegeTier.T3_MANAGED)
        val verdict = CapabilityCatalogGate.enforcing(catalogWith(entry)).evaluate("managed_probe")
        assertEquals(CatalogDenialReason.TIER_NOT_PROVISIONED, deniedReason(verdict))
    }

    @Test
    fun `explicit provisioning raises the ceiling`() {
        val gate =
            CapabilityCatalogGate.enforcing(
                catalogWith(
                    entryAtTier("managed_probe", PrivilegeTier.T3_MANAGED),
                    entryAtTier("platform_probe", PrivilegeTier.T5_PLATFORM),
                ),
                provisionedMaxTier = PrivilegeTier.T3_MANAGED,
            )

        assertInstanceOf(CapabilityVerdict.Allowed::class.java, gate.evaluate("managed_probe"))
        assertEquals(CatalogDenialReason.TIER_NOT_PROVISIONED, deniedReason(gate.evaluate("platform_probe")))
    }

    @Test
    fun `device catalog tier ceiling never exceeds the test tier`() {
        // Catalog data itself is ceiling-clamped: the device ships only T1_APP/T2_TEST
        // capabilities, so managed-grade tiers exist in the schema but never in the catalog.
        val deviceCatalog = CapabilityCatalog.deviceCatalog()
        deviceCatalog.toolNames.forEach { toolName ->
            val entry = deviceCatalog.forTool(toolName)!!
            assertTrue(entry.privilegeTier.rank <= PrivilegeTier.T2_TEST.rank)
        }
    }
}
