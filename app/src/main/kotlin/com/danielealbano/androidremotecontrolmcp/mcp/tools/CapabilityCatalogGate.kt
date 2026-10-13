package com.danielealbano.androidremotecontrolmcp.mcp.tools

/**
 * Why the capability catalog refused a dispatch (typed, logged via the TOOL_CALL marker).
 */
enum class CatalogDenialReason {
    /** The requested tool has no catalog entry. */
    NOT_IN_CATALOG,

    /** The tool exists but its privilege tier exceeds the provisioned ceiling. */
    TIER_NOT_PROVISIONED,
}

/** Outcome of evaluating one dispatch against the capability catalog. */
sealed interface CapabilityVerdict {
    /**
     * Dispatch may proceed. [entry] is the catalog entry of the tool, or null when the gate
     * is inactive (upstream-permissive builds keep no catalog evidence on the hot path).
     */
    data class Allowed(
        val entry: CapabilityEntry?,
    ) : CapabilityVerdict

    /** Dispatch must be rejected before execution; [detail] is the operator-facing reason. */
    data class Denied(
        val reason: CatalogDenialReason,
        val detail: String,
    ) : CapabilityVerdict
}

/**
 * Pre-dispatch gate that admits only catalog-listed tools with a privilege tier at or below
 * the provisioned ceiling. Composes with the existing [ToolPolicyGate]: the catalog verdict
 * runs first, the policy verdict second, and denied dispatches never reach the tool handler.
 *
 * On hardened builds the ceiling defaults to [DEFAULT_PROVISIONED_TIER] (T2_TEST), so
 * T3_MANAGED and above stay OFF unless explicitly provisioned via [enforcing]; the device
 * catalog never contains tiers above T2_TEST, so unknown tools are rejected as
 * NOT_IN_CATALOG before execution. On gms/foss builds the gate is [INACTIVE] and every
 * dispatch is allowed, preserving upstream-permissive behavior.
 */
class CapabilityCatalogGate(
    private val catalog: CapabilityCatalog,
    private val provisionedMaxTier: PrivilegeTier = DEFAULT_PROVISIONED_TIER,
    private val active: Boolean,
) {
    /** Evaluates one dispatch and returns the typed verdict. */
    fun evaluate(toolName: String): CapabilityVerdict =
        when {
            !active -> CapabilityVerdict.Allowed(entry = null)
            else -> evaluateEnforcing(toolName)
        }

    private fun evaluateEnforcing(toolName: String): CapabilityVerdict {
        val entry = catalog.forTool(toolName)
        val tierExceedsCeiling =
            entry != null && entry.privilegeTier.rank > provisionedMaxTier.rank
        return when {
            entry == null -> {
                CapabilityVerdict.Denied(
                    reason = CatalogDenialReason.NOT_IN_CATALOG,
                    detail = "Tool '$toolName' is not listed in the capability catalog.",
                )
            }

            tierExceedsCeiling -> {
                CapabilityVerdict.Denied(
                    reason = CatalogDenialReason.TIER_NOT_PROVISIONED,
                    detail =
                        "Tool '$toolName' requires privilege tier ${entry.privilegeTier.wireName} " +
                            "which exceeds the provisioned ceiling ${provisionedMaxTier.wireName}.",
                )
            }

            else -> {
                CapabilityVerdict.Allowed(entry)
            }
        }
    }

    companion object {
        /**
         * Hardened default ceiling: automation-grade (T2_TEST) capabilities are available,
         * managed-grade tiers are OFF by default and must be provisioned explicitly.
         */
        val DEFAULT_PROVISIONED_TIER: PrivilegeTier = PrivilegeTier.T2_TEST

        /** Upstream-permissive gate: every dispatch is allowed, no catalog enforcement. */
        val INACTIVE: CapabilityCatalogGate =
            CapabilityCatalogGate(
                catalog = CapabilityCatalog.of(emptyList()),
                active = false,
            )

        /** Enforcing gate over [catalog] with an explicit (default T2_TEST) tier ceiling. */
        fun enforcing(
            catalog: CapabilityCatalog,
            provisionedMaxTier: PrivilegeTier = DEFAULT_PROVISIONED_TIER,
        ): CapabilityCatalogGate =
            CapabilityCatalogGate(
                catalog = catalog,
                provisionedMaxTier = provisionedMaxTier,
                active = true,
            )
    }
}
