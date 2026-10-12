package com.danielealbano.androidremotecontrolmcp.mcp

import android.util.Log
import com.danielealbano.androidremotecontrolmcp.BuildConfig
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.header
import io.ktor.server.response.respondText
import io.ktor.util.pipeline.PipelinePhase
import io.modelcontextprotocol.kotlin.sdk.types.McpJson
import kotlinx.serialization.Serializable

/** Maximum accepted length for an `Origin`/authority header before it is treated as malformed. */
private const val MAX_ORIGIN_LENGTH = 1024

/** Maximum number of digits in a parseable port. */
private const val MAX_PORT_DIGITS = 5

/** Highest valid TCP port. */
private const val MAX_VALID_PORT = 65535

/** Loopback hosts that are always trusted as the request target for the hardened topology.
 * IPv6 literals are stored in canonical bracketed form, matching [parseAuthority]'s output. */
private val LOOPBACK_HOSTS =
    setOf("localhost", "127.0.0.1", "[::1]", "[::ffff:127.0.0.1]")

/** Default port for `http://` URLs; folded away during origin normalization. */
private const val HTTP_DEFAULT_PORT = 80

/** Default port for `https://` URLs; folded away during origin normalization. */
private const val HTTPS_DEFAULT_PORT = 443

/**
 * Response body returned when the request origin/host policy denies a request.
 */
@Serializable
data class OriginErrorResponse(
    val error: String,
    val message: String,
)

/**
 * Per-request inputs the policy evaluates. [scheme] is the scheme of the client-facing request URI
 * as Ktor derived it from the request line/URI (NOT from any `X-Forwarded-*` header, which the
 * policy must never trust); [hostHeader] is the raw `Host` header; [originHeader] is the raw
 * `Origin` header (absent for non-browser clients).
 */
data class RequestOriginFacts(
    val scheme: String,
    val hostHeader: String?,
    val originHeader: String?,
) {
    /** Convenience facts builder for callers that know the request authority directly. */
    companion object {
        fun of(
            scheme: String,
            hostHeader: String,
            originHeader: String? = null,
        ): RequestOriginFacts = RequestOriginFacts(scheme, hostHeader, originHeader)
    }
}

/**
 * Outcome of evaluating [RequestOriginFacts] against the policy. [Denied.reason] is a stable,
 * service-side diagnostic label (logged, never reflected to the client).
 */
sealed interface OriginDecision {
    /** Data object for the allowed outcome (request proceeds to CORS, then auth). */
    data object Allowed : OriginDecision

    /** Denial with a diagnostic reason string. */
    data class Denied(
        val reason: String,
    ) : OriginDecision
}

/**
 * Deterministic Origin/Host enforcement for the hardened lab build (handoff H-01).
 *
 * Hardened semantics (`anyOrigin == false`):
 * - The request authority is the client-controlled `Host` header when present; otherwise the
 *   server's local endpoint (deficient/absent `Host`, e.g. HTTP/2-style clients). Missing, blank or
 *   malformed authority → deny. DNS-rebinding / arbitrary public `Host` headers → deny unless the
 *   host is loopback or one of the centrally provisioned [approvedOrigins] hosts.
 * - Absent `Origin` → allow (native/non-browser clients); this is NOT authentication — bearer/OAuth
 *   auth still applies downstream in the `McpAuth` phase.
 * - `Origin: null`, wildcards, userinfo, path/query/fragment, percent-encoding, non-ASCII
 *   (punycode-mixing), unknown schemes, bad ports → deny.
 * - Same-origin requests (normalized `Origin` == normalized request scheme+`Host`) → allow.
 * - Cross-origin requests whose normalized origin is exactly in [approvedOrigins] → allow
 *   (single approved loopback/gateway topology; suffix or subdomain matches are NOT accepted).
 * - A valid auth token does not excuse an invalid origin: this plugin is registered in a dedicated
 *   phase BEFORE Ktor's `Plugins` phase, so it runs before the CORS plugin (`Validators` phase since
 *   Ktor 3.5) and before `McpAuth`.
 *
 * Non-hardened semantics (`anyOrigin == true`, gms/foss): pure pass-through allow — every request
 * proceeds exactly as before this policy existed, preserving Ktor's `anyHost()` CORS behavior and
 * the documented trade-off in [configureCors].
 *
 * Use [create] (fail fast on hardened/anyOrigin conflict or malformed allowlist entries) — the
 * [McpRequestOriginPolicyPlugin] calls it at install time, so a misconfigured hardened server refuses to
 * start rather than serving with a weakened origin policy.
 */
class RequestOriginPolicy private constructor(
    /** Whether every request is allowed (non-hardened pass-through mode). */
    val anyOrigin: Boolean,
    /** Whether this is the hardened lab build. */
    val isLabHardened: Boolean,
    approvedOrigins: Collection<String>,
) {
    /** Normalized (`scheme://host[:port]`, default ports folded, hosts lowercased) allowlist origins. */
    private val approvedOriginsNormalized: Set<String> =
        approvedOrigins.mapTo(LinkedHashSet()) { origin ->
            normalizeOrigin(origin) ?: error("Invalid approved origin '$origin'")
        }

    /** Hosts accepted in the `Host` header: loopback plus the hosts of [approvedOrigins]. */
    private val approvedHosts: Set<String> =
        LOOPBACK_HOSTS +
            approvedOriginsNormalized.mapTo(LinkedHashSet()) { origin ->
                // Entries are validated at creation, so authority parsing cannot fail here.
                parseAuthority(origin.substringAfter("://")).let { parsed ->
                    parsed?.host ?: error("Invalid approved origin '$origin'")
                }
            }

    /**
     * Evaluates the request facts. Always a total function: any unparsable input denies (hardened)
     * or the whole evaluation is bypassed (pass-through), never throws per-request.
     */
    fun evaluate(facts: RequestOriginFacts): OriginDecision =
        if (anyOrigin) {
            OriginDecision.Allowed
        } else {
            evaluateHardened(facts)
        }

    private fun evaluateHardened(facts: RequestOriginFacts): OriginDecision =
        parseAuthority(facts.hostHeader.orEmpty())?.let { serverAuthority ->
            when {
                serverAuthority.host !in approvedHosts -> {
                    OriginDecision.Denied(REASON_HOST_NOT_APPROVED)
                }

                else -> {
                    evaluateOriginGate(facts, serverAuthority)
                }
            }
        } ?: OriginDecision.Denied(REASON_HOST_MISSING_OR_MALFORMED)

    private fun evaluateOriginGate(
        facts: RequestOriginFacts,
        serverAuthority: ParsedAuthority,
    ): OriginDecision {
        val origin = facts.originHeader?.trim().orEmpty()
        val normalizedOrigin = origin.takeUnless { it.isEmpty() }?.let { normalizeOrigin(it) }
        return when {
            origin.isEmpty() -> {
                // Non-browser client (native MCP clients, curl). Absent Origin is NOT authentication:
                // authorization still applies downstream.
                OriginDecision.Allowed
            }

            normalizedOrigin == null -> {
                OriginDecision.Denied(REASON_ORIGIN_MALFORMED)
            }

            normalizedOrigin == serverOrigin(facts.scheme, serverAuthority) -> {
                OriginDecision.Allowed
            }

            normalizedOrigin in approvedOriginsNormalized -> {
                OriginDecision.Allowed
            }

            else -> {
                OriginDecision.Denied(REASON_ORIGIN_NOT_APPROVED)
            }
        }
    }

    /**
     * Ktor CORS predicate for the hardened build: exact allowlist membership after normalization
     * (defense in depth behind [evaluate] — the policy already denied unapproved origins earlier).
     */
    fun isApprovedCrossOrigin(rawOrigin: String): Boolean {
        val normalized = normalizeOrigin(rawOrigin) ?: return false
        return normalized in approvedOriginsNormalized
    }

    private fun serverOrigin(
        scheme: String,
        serverAuthority: ParsedAuthority,
    ): String? {
        val normalizedScheme = scheme.lowercase()
        if (normalizedScheme != "http" && normalizedScheme != "https") {
            return null
        }
        val portSuffix =
            when {
                serverAuthority.port == null -> ""
                (normalizedScheme == "http" && serverAuthority.port == HTTP_DEFAULT_PORT) -> ""
                (normalizedScheme == "https" && serverAuthority.port == HTTPS_DEFAULT_PORT) -> ""
                else -> ":${serverAuthority.port}"
            }
        return "$normalizedScheme://${serverAuthority.host}$portSuffix"
    }

    /**
     * Creates the policy, failing fast on hardened-build misconfiguration. Called when the server
     * plugins are installed (server start), so a misconfigured hardened build aborts startup:
     * - a hardened build must NEVER widen to any-origin (the Ktor CORS `anyHost()` posture);
     * - every allowlist entry must be an exact, normalized `http(s)://host[:port]` origin —
     *   wildcards, suffixes, userinfo, paths, non-ASCII or unknown schemes are refused.
     *
     * @param isLabHardened Whether the running flavor is the hardened lab build.
     * @param approvedOrigins Centrally provisioned cross-origin allowlist (exact origins).
     * @param allowAnyOrigin Permissive override; refused on hardened builds, implicit for
     *   non-hardened builds (which keep their documented permissive CORS behavior).
     */
    companion object {
        /** Reason: `Host` header absent, blank or unparsable. */
        const val REASON_HOST_MISSING_OR_MALFORMED = "host-missing-or-malformed"

        /** Reason: `Host` header host not in the approved loopback/gateway topology. */
        const val REASON_HOST_NOT_APPROVED = "host-not-approved"

        /** Reason: `Origin` header present but not a well-formed http(s) origin. */
        const val REASON_ORIGIN_MALFORMED = "origin-malformed"

        /** Reason: well-formed origin, but not same-origin nor in the approved allowlist. */
        const val REASON_ORIGIN_NOT_APPROVED = "origin-not-approved"

        fun create(
            isLabHardened: Boolean,
            approvedOrigins: Collection<String> = emptyList(),
            allowAnyOrigin: Boolean = false,
        ): RequestOriginPolicy {
            if (isLabHardened && allowAnyOrigin) {
                throw IllegalStateException(
                    "RequestOriginPolicy: a hardened build must refuse any-origin CORS (anyHost())",
                )
            }
            if (isLabHardened) {
                approvedOrigins.forEach { entry ->
                    if (normalizeOrigin(entry) == null) {
                        throw IllegalStateException(
                            "RequestOriginPolicy: invalid approved origin '$entry' " +
                                "(expected exact http(s)://host[:port], no wildcards/paths/credentials)",
                        )
                    }
                }
            }
            return RequestOriginPolicy(
                anyOrigin = !isLabHardened,
                isLabHardened = isLabHardened,
                approvedOrigins = if (isLabHardened) approvedOrigins else emptyList(),
            )
        }
    }
}

/**
 * Configuration for [McpRequestOriginPolicyPlugin]: carries the resolved [RequestOriginPolicy].
 * The default resolves to this build's flavor default (hardened → strict topology enforcement with
 * an EMPTY cross-origin allowlist; gms/foss → permissive pass-through). Callers override [policy]
 * (typically via [installMcpBasePlugins]) to provision an allowlist; [RequestOriginPolicy.create]
 * fails fast on hardened misconfiguration, so an invalid policy aborts server start at install time.
 */
class McpRequestOriginPluginConfig {
    /** Resolved enforcement policy applied to every request. */
    var policy: RequestOriginPolicy = RequestOriginPolicy.create(isLabHardened = BuildConfig.LAB_HARDENED)
}

private const val TAG = "MCP:RequestOriginPolicy"

/** Application plugin name of [McpRequestOriginPolicyPlugin]; also used in diagnostics. */
const val MCP_REQUEST_ORIGIN_PLUGIN_NAME = "McpRequestOriginPolicy"

/**
 * The hardened-build Origin/Host policy plugin. Applies [McpRequestOriginPluginConfig.policy] to
 * every request; see [RequestOriginPolicy] for semantics and [installMcpBasePlugins] for the
 * mandatory plugin ordering.
 */
val McpRequestOriginPolicyPlugin =
    createApplicationPlugin(
        name = MCP_REQUEST_ORIGIN_PLUGIN_NAME,
        createConfiguration = ::McpRequestOriginPluginConfig,
    ) {
        val policy = pluginConfig.policy

        // Registered on a dedicated phase inserted BEFORE the built-in `Plugins` phase so origin
        // enforcement precedes every other plugins hook, the CORS plugin (Ktor 3.5 `Validators`
        // phase) and auth. Intercepting a phase (rather than `onCall`) provides the `finish()` that
        // stops the remaining pipeline (CORS, auth, routing) from running on a denial — the same
        // mechanism [McpAuthPlugin] uses for its own denials.
        val originPhase = PipelinePhase("McpRequestOriginPolicy")
        application.insertPhaseBefore(ApplicationCallPipeline.Plugins, originPhase)
        application.intercept(originPhase) {
            val call = context
            val facts = facts(call)
            val decision = policy.evaluate(facts)
            if (decision is OriginDecision.Denied) {
                // Denial details stay in service logs; the response body is deliberately generic.
                Log.w(
                    TAG,
                    "Request denied by origin/host policy: ${decision.reason} " +
                        "(host=${facts.hostHeader}, origin=${facts.originHeader})",
                )
                call.respondText(
                    McpJson.encodeToString(
                        OriginErrorResponse.serializer(),
                        OriginErrorResponse(
                            error = "origin_not_allowed",
                            message = "Request origin or host is not allowed.",
                        ),
                    ),
                    ContentType.Application.Json,
                    HttpStatusCode.Forbidden,
                )
                finish()
            }
        }
    }

private fun facts(call: ApplicationCall): RequestOriginFacts {
    val local = call.request.local
    return RequestOriginFacts(
        // Server-side scheme of the connection point — NOT `request.origin`/X-Forwarded-* based, so
        // spoofed proxy headers cannot influence identity or external URL derivation.
        scheme = local.scheme,
        // Effective request authority: the client-controlled `Host` header when present; otherwise
        // the server's local endpoint (requests with a deficient/absent Host, e.g. some
        // HTTP/2-style clients). The fallback is server-derived, so it cannot be spoofed.
        hostHeader = call.request.header(HttpHeaders.Host) ?: local.localHost,
        originHeader = call.request.header(HttpHeaders.Origin),
    )
}

/** Canonical (`host`, `port?`) pair parsed from an Origin/Host authority component. */
internal data class ParsedAuthority(
    val host: String,
    val port: Int?,
)

/**
 * Parses a `host[:port]` (or bracketed IPv6 `[host]:port`) authority deterministically and strictly:
 * printable ASCII only; host limited to `[a-z0-9.-]` (lowercased, trailing dots stripped) which
 * rejects percent-encoding, userinfo, wildcards, spaces and any non-ASCII/punycode-mixing; at most
 * one unbracketed colon (bare IPv6 is refused — brackets are mandatory); port digits in `1..65535`.
 * The returned host is lowercase; bracketed IPv6 literals keep their brackets. Returns null for
 * anything that does not parse (callers fail closed).
 */
internal fun parseAuthority(authority: String): ParsedAuthority? =
    if (authority.isEmpty() || authority.length > MAX_ORIGIN_LENGTH) {
        null
    } else {
        splitAuthority(authority)?.let { (hostPart, portPart) ->
            parseHostToken(hostPart, bracketed = authority.startsWith("["))?.let { host ->
                buildAuthority(host, portPart)
            }
        }
    }

/** Builds the final authority: a `null` port part means "no port" (valid); anything else must be a valid port. */
private fun buildAuthority(
    host: String,
    portPart: String?,
): ParsedAuthority? =
    when (portPart) {
        null -> ParsedAuthority(host = host, port = null)
        else -> parsePortToken(portPart)?.let { port -> ParsedAuthority(host = host, port = port) }
    }

/**
 * Splits `[host]:port` / `host[:port]` into (host part, port part or null). Bracketed literals
 * must end at `]` followed by nothing or `:port`; plain authorities may contain at most one colon
 * (bare IPv6 is refused — brackets are mandatory).
 */
private fun splitAuthority(authority: String): Pair<String, String?>? =
    if (authority.startsWith("[")) {
        splitBracketedAuthority(authority)
    } else {
        splitPlainAuthority(authority)
    }

private fun splitBracketedAuthority(authority: String): Pair<String, String?>? =
    authority.indexOf(']').takeIf { it >= 0 }?.let { closing ->
        val remainder = authority.substring(closing + 1)
        when {
            // Anything after `]` other than empty or `:port` makes the authority unparsable.
            remainder.isEmpty() -> authority.substring(1, closing) to null

            remainder.startsWith(":") -> authority.substring(1, closing) to remainder.substring(1)

            else -> null
        }
    }

private fun splitPlainAuthority(authority: String): Pair<String, String?>? {
    val colon = authority.indexOf(':')
    return if (colon < 0) {
        authority to null
    } else {
        when {
            authority.indexOf(':', colon + 1) >= 0 -> null
            else -> authority.substring(0, colon) to authority.substring(colon + 1)
        }
    }
}

/** Canonical lowercased host token (bracketed IPv6 keeps its brackets); trailing dots stripped. */
private fun parseHostToken(
    hostPart: String,
    bracketed: Boolean,
): String? {
    val hostToken = hostPart.lowercase().trimEnd { it == '.' }
    val allowedHostTokens = if (bracketed) IPV6_HOST_TOKENS else HOST_TOKENS
    // IPv6 literals keep their brackets in the canonical host so Host-header values and
    // allowlist-derived hosts are always compared in one representation.
    return when {
        hostToken.isEmpty() || hostToken.any { it !in allowedHostTokens } -> null
        bracketed -> "[$hostToken]"
        else -> hostToken
    }
}

/** Parses a decimal port component (`null` component means "no port"); rejects all else. */
private fun parsePortToken(portPart: String?): Int? =
    when {
        portPart == null -> null
        portPart.isEmpty() || portPart.length > MAX_PORT_DIGITS -> null
        portPart.any { it !in '0'..'9' } -> null
        else -> portPart.toInt().takeIf { it in 1..MAX_VALID_PORT }
    }

/** Characters allowed in a parsed (lowercased) hostname token. */
private const val HOST_TOKENS = "abcdefghijklmnopqrstuvwxyz0123456789.-"

/** Characters allowed inside a bracketed IPv6 literal (lowercased). */
private const val IPV6_HOST_TOKENS = "0123456789abcdef:."

/**
 * Normalizes an `Origin` header/allowlist entry to the canonical comparison form
 * `scheme://host[:port]` (scheme and host lowercased, trailing dot stripped, default ports folded
 * per RFC 3986 semantics so `https://h:443` == `https://h`). Returns null for anything that is not
 * an exact, well-formed `http(s)://authority` origin — this deliberately rejects: `"null"` and
 * `"*"` literals, wildcards, userinfo (`@`), paths/queries/fragments, percent-encoding, whitespace,
 * non-ASCII (so Unicode/punycode twins can never collide with an ASCII allowlist entry), and any
 * scheme other than http/https.
 */
internal fun normalizeOrigin(raw: String): String? =
    if (raw.isEmpty() || raw.length > MAX_ORIGIN_LENGTH) {
        null
    } else {
        splitOrigin(raw)?.let { (scheme, authority) ->
            parseAuthority(authority)?.let { parsed ->
                "$scheme://${parsed.host}${originPortSuffix(scheme, parsed)}"
            }
        }
    }

/**
 * Splits `scheme://authority` (lowercased scheme, http/https only) so normalization can reuse the
 * strict authority parser. Rejects empty authority and any scheme other than http/https.
 */
private fun splitOrigin(raw: String): Pair<String, String>? {
    val separator = raw.indexOf("://")
    if (separator <= 0) {
        return null
    }
    val scheme = raw.substring(0, separator).lowercase()
    val authority = raw.substring(separator + 3)
    return if (scheme in HTTP_SCHEMES && authority.isNotEmpty()) {
        scheme to authority
    } else {
        null
    }
}

/** RFC 3986 default-port folding: `http:80` and `https:443` become the bare authority. */
private fun originPortSuffix(
    scheme: String,
    parsed: ParsedAuthority,
): String =
    when {
        parsed.port == null -> ""
        scheme == "http" && parsed.port == HTTP_DEFAULT_PORT -> ""
        scheme == "https" && parsed.port == HTTPS_DEFAULT_PORT -> ""
        else -> ":${parsed.port}"
    }

private val HTTP_SCHEMES = setOf("http", "https")
