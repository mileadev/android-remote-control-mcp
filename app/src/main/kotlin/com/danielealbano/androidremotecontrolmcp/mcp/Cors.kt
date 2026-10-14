package com.danielealbano.androidremotecontrolmcp.mcp

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.cors.routing.CORS

/** Request header carrying the negotiated MCP protocol version. */
const val MCP_PROTOCOL_VERSION_HEADER = "mcp-protocol-version"

/** Request/response header carrying the Streamable HTTP session id. */
const val MCP_SESSION_ID_HEADER = "mcp-session-id"

/** Preflight cache lifetime (1 hour) — avoids re-issuing a preflight for nearly every `/mcp` call. */
private const val CORS_MAX_AGE_SECONDS = 3600L

/**
 * Installs Origin/Host enforcement plus CORS so browser-based MCP clients (e.g. the MCP Inspector)
 * can complete the OAuth discovery/DCR/authorize flow AND the `/mcp` protocol exchange, while the
 * hardened lab build refuses any unapproved cross-origin or cross-host traffic.
 *
 * Flavors (see [RequestOriginPolicy]):
 * - gms/foss ([RequestOriginPolicy.anyOrigin]): unchanged behavior — `anyHost()` CORS. Auth is NOT
 *   weakened: `/mcp` still requires the bearer or OAuth token (which a cross-origin page cannot
 *   obtain) and the OAuth flow is still gated by the on-device number-match approval. Credentials
 *   mode is deliberately NOT enabled (auth travels in the `Authorization` header, not cookies),
 *   which is what permits the wildcard origin — the two are mutually exclusive per the CORS spec.
 *   For non-browser clients (Claude.ai backend, `mcp-remote`, Claude Desktop) there is no `Origin`
 *   header, so the CORS plugin is a complete no-op and the wildcard ACAO is never even emitted.
 *   **Trade-off (open mode / DNS rebinding)** — see PROJECT.md "Network Security": no Origin/Host
 *   allowlist exists on these flavors because the device's public host is dynamic (changing IPs,
 *   Cloudflare/ngrok tunnels, `public_url_override`), so any static allowlist would break remote
 *   access. Stay on loopback and keep at least one auth method enabled unless the network is trusted.
 * - labHardened (`!policy.anyOrigin`): [McpRequestOriginPolicyPlugin] (which precedes this plugin
 *   and [McpAuthPlugin]) already denied invalid/unapproved origins — including malicious
 *   preflights, bad `Host` headers and `Origin: null` — with 403 BEFORE CORS runs. The hardened
 *   CORS config therefore never calls `anyHost()` (structurally refused: [RequestOriginPolicy.create]
 *   aborts install/server start on any-origin policies) and instead reflects EXACTLY the origins
 *   approved by [policy]. Cross-origin responses carry no wildcard ACAO, ever: the centrally
 *   provisioned allowlist holds exact origins only, and subdomain/suffix/punycode variants are
 *   rejected by the policy's strict normalization.
 *
 * Must run BEFORE [com.danielealbano.androidremotecontrolmcp.mcp.auth.McpAuthPlugin], which fails
 * closed on any token-less request to `/mcp` — including a preflight `OPTIONS`, which carries no
 * `Authorization` header. The full request order enforced by [installMcpBasePlugins] is:
 * [McpRequestOriginPolicyPlugin] (`Plugins` phase) → this CORS plugin (`Validators` phase since
 * Ktor 3.5) → [McpAuthPlugin] (phase inserted after `Validators`, before `Call`). So the origin
 * policy rejects first; CORS answers the surviving preflights and decorates responses; auth runs
 * last. This wiring is centralized in [installMcpBasePlugins] so production and tests cannot drift.
 *
 * Response headers are exposed so browser clients can read them via `fetch()` (non-safelisted
 * response headers are hidden from JS otherwise):
 * - [MCP_SESSION_ID_HEADER] — the session id the Streamable HTTP transport returns, replayed on
 *   follow-up requests.
 * - `WWW-Authenticate` — carries the RFC 9728 `resource_metadata` pointer on a 401, which is how a
 *   browser MCP client discovers the OAuth authorization server. Not exposing it would defeat the
 *   header the auth plugin sends specifically for this discovery.
 *
 * [MCP_PROTOCOL_VERSION_HEADER] is allowed as a REQUEST header (MCP 2025-06-18 clients send it) but
 * is NOT exposed, because the SDK transport does not emit it as a response header.
 */
fun Application.configureCors(policy: RequestOriginPolicy) {
    install(CORS) {
        if (policy.anyOrigin) {
            // gms/foss: unchanged permissive posture (see class KDoc for the documented trade-off).
            anyHost()
        } else {
            // labHardened: exact-origin allowlist only — reflects precisely the request origin for
            // approved (cross-origin) requests; never emits a wildcard ACAO.
            allowOrigins(policy::isApprovedCrossOrigin)
        }
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Delete)
        allowMethod(HttpMethod.Options)
        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(MCP_PROTOCOL_VERSION_HEADER)
        allowHeader(MCP_SESSION_ID_HEADER)
        exposeHeader(MCP_SESSION_ID_HEADER)
        exposeHeader(HttpHeaders.WWWAuthenticate)
        maxAgeInSeconds = CORS_MAX_AGE_SECONDS
        // MCP POSTs use `Content-Type: application/json`, a non-simple content type whose preflight
        // Ktor rejects unless explicitly allowed.
        allowNonSimpleContentTypes = true
    }
}
