package com.danielealbano.androidremotecontrolmcp.mcp.auth

/**
 * Startup gate for the hardened lab distribution (`BuildConfig.LAB_HARDENED == true`).
 *
 * Enforces the repository-hardening requirement H-02: the MCP server may never start
 * with a configuration that would accept unauthenticated clients. Under the hardened
 * policy this means:
 *
 *  1. A configuration with both bearer-token auth and OAuth disabled (i.e. an OPEN
 *     server) is refused outright.
 *  2. Bearer-token auth is mandatory: OAuth may be layered on top of it, but the
 *     bearer token check must remain enforced, so a bearer-disabled configuration is
 *     refused even when OAuth alone would still authenticate clients.
 *  3. When bearer auth is enabled, an actual non-blank token must be configured, so a
 *     missing token can never degrade into an OPEN server at runtime.
 *
 * The gate is fail-closed by construction: any configuration that does not satisfy the
 * policy raises an [IllegalStateException] carrying an explicit error message, which
 * [com.danielealbano.androidremotecontrolmcp.mcp.McpServer.start] lets propagate so the
 * server never binds a socket and the service surfaces the cause as a start failure.
 *
 * The upstream `gms` and `foss` flavors keep their current behavior: [validate] returns
 * immediately when [hardened] is `false`, so upstream configurations (including the
 * explicitly-supported OPEN one) remain valid there.
 */
object LabAuthGate {
    private const val DUAL_OFF_REFUSAL =
        "Refuses to start: both auth methods are disabled, leaving the MCP server " +
            "OPEN to unauthenticated clients. Enable the enforced bearer token " +
            "(and optionally approved OAuth) before starting the hardened MCP server."

    private const val BEARER_MANDATORY_REFUSAL =
        "Refuses to start: authenticated MCP clients must pass the enforced bearer " +
            "token check. OAuth may be layered on top, but bearer auth itself may not " +
            "be disabled in the hardened MCP server."

    private const val BLANK_TOKEN_REFUSAL =
        "Refuses to start: bearer auth is enabled but no bearer token is configured. " +
            "Set a valid bearer token so hardened MCP clients are authenticated."

    /**
     * Validates the server auth configuration for the given distribution policy.
     *
     * @param hardened Whether the enforcing (lab-hardened) policy applies.
     * @param bearerTokenEnabled Whether the bearer-token auth method is enabled.
     * @param expectedToken The configured bearer token; must be non-blank when bearer
     *   auth is enabled and the hardened policy applies.
     * @param oauthEnabled Whether the OAuth 2.1 auth method is enabled.
     * @throws IllegalStateException When the hardened policy applies and the
     *   configuration would authenticate requests with neither method, would drop the
     *   mandatory bearer-token check, or has no bearer token configured.
     */
    fun validate(
        hardened: Boolean,
        bearerTokenEnabled: Boolean,
        expectedToken: String,
        oauthEnabled: Boolean,
    ) {
        if (!hardened) {
            return
        }
        val reason = refusalReasonFor(bearerTokenEnabled, expectedToken, oauthEnabled)
        if (reason != null) {
            throw IllegalStateException(reason)
        }
    }

    /**
     * Returns the explicit refusal message when the hardened policy forbids a
     * configuration, or null when the configuration may start.
     */
    private fun refusalReasonFor(
        bearerTokenEnabled: Boolean,
        expectedToken: String,
        oauthEnabled: Boolean,
    ): String? =
        when {
            !bearerTokenEnabled && !oauthEnabled -> DUAL_OFF_REFUSAL
            !bearerTokenEnabled -> BEARER_MANDATORY_REFUSAL
            expectedToken.isBlank() -> BLANK_TOKEN_REFUSAL
            else -> null
        }
}
