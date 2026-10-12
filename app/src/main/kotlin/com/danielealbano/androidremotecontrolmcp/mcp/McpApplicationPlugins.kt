package com.danielealbano.androidremotecontrolmcp.mcp

import com.danielealbano.androidremotecontrolmcp.mcp.auth.McpAuthConfig
import com.danielealbano.androidremotecontrolmcp.mcp.auth.McpAuthPlugin
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.modelcontextprotocol.kotlin.sdk.types.McpJson

/**
 * Installs the MCP application base plugins in the ONE canonical order shared by production
 * ([McpServer.configureApplication]) and the integration tests:
 *
 * 1. [ContentNegotiation] with `json(McpJson)` — required by the SDK Streamable HTTP transport.
 * 2. [McpRequestOriginPolicyPlugin] — hardened Origin/Host enforcement (`Plugins` phase).
 * 3. [configureCors] — Ktor's CORS plugin (`Validators` phase since Ktor 3.5).
 * 4. [McpAuthPlugin] — combined bearer/OAuth authentication, configured by the caller.
 *
 * The execution order (so denied origins never reach CORS or auth, token-less browser preflight
 * `OPTIONS` are answered by CORS instead of being failed closed by auth, and 401s still carry
 * `Access-Control-Allow-Origin`) is guaranteed by Ktor phases — [McpRequestOriginPolicyPlugin]'s
 * `onCall` hooks run in `Plugins`, CORS registers in `Validators`, and [McpAuthPlugin] runs in a
 * phase inserted after `Validators` — NOT by install order. Centralizing the wiring here still
 * keeps production and tests identical, and the integration tests exercise it directly so a
 * regression cannot pass unnoticed.
 *
 * The origin policy is resolved from [configureOriginPolicy] exactly once, BEFORE any plugin is
 * installed: [RequestOriginPolicy.create] fails fast on hardened misconfiguration (any-origin
 * override or malformed allowlist entries), so a misconfigured hardened server aborts at start
 * rather than serving with a weakened policy.
 *
 * @param configureOriginPolicy Caller-supplied [McpRequestOriginPluginConfig] block — typically
 *   provisions `policy` from `ServerConfig.approvedOrigins` (centrally provisioned allowlist).
 * @param configureAuth Caller-supplied [McpAuthConfig] block (tokens, OAuth validator, exclusions).
 */
fun Application.installMcpBasePlugins(
    configureOriginPolicy: McpRequestOriginPluginConfig.() -> Unit = {},
    configureAuth: McpAuthConfig.() -> Unit,
) {
    install(ContentNegotiation) { json(McpJson) }
    val originPolicy = McpRequestOriginPluginConfig().apply(configureOriginPolicy).policy
    install(McpRequestOriginPolicyPlugin) { policy = originPolicy }
    configureCors(originPolicy)
    install(McpAuthPlugin, configureAuth)
}
