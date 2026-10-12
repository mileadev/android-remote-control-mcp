package com.danielealbano.androidremotecontrolmcp.mcp

import com.danielealbano.androidremotecontrolmcp.BuildConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * Unit tests for [RequestOriginPolicy]: origin normalization/authority parsing, hardened
 * fail-fast creation, the hardened evaluate() decisions, and the permissive gms/foss
 * pass-through. Complements [com.danielealbano.androidremotecontrolmcp.integration.AuthAndOriginLabTest]
 * which exercises the full Ktor plugin wiring end to end.
 */
@DisplayName("RequestOriginPolicy")
class RequestOriginPolicyTest {
    private val approvedOrigin = "https://station.lab.example"

    @Nested
    @DisplayName("normalizeOrigin")
    inner class NormalizeOriginTests {
        @Test
        fun `folds default ports and lowercases scheme and host`() {
            assertEquals("http://localhost", normalizeOrigin("HTTP://LocalHost:80"))
            assertEquals("https://station.lab.example", normalizeOrigin("HTTPS://Station.Lab.Example:443"))
            assertEquals("https://station.lab.example:8443", normalizeOrigin("https://Station.Lab.Example:8443"))
        }

        @Test
        fun `strips a single trailing dot from the host`() {
            assertEquals("https://station.lab.example", normalizeOrigin("https://station.lab.example."))
        }

        @Test
        fun `accepts ipv6 literal origins`() {
            assertEquals("https://[::1]:8443", normalizeOrigin("https://[::1]:8443"))
            assertEquals("https://[::1]", normalizeOrigin("https://[::1]"))
            assertEquals("https://[::ffff:127.0.0.1]", normalizeOrigin("https://[::ffff:127.0.0.1]"))
        }

        @Test
        fun `keeps explicit non-default port`() {
            assertEquals("http://localhost:8080", normalizeOrigin("http://localhost:8080"))
        }

        @Test
        fun `rejects null and wildcard literals`() {
            assertNull(normalizeOrigin("null"))
            assertNull(normalizeOrigin("*"))
        }

        @Test
        fun `rejects paths queries fragments and userinfo`() {
            assertNull(normalizeOrigin("https://station.lab.example/path"))
            assertNull(normalizeOrigin("https://station.lab.example?q=1"))
            assertNull(normalizeOrigin("https://station.lab.example#frag"))
            assertNull(normalizeOrigin("https://user@station.lab.example"))
            assertNull(normalizeOrigin("https://station.lab.example/../../etc"))
        }

        @Test
        fun `rejects host suffix tricks`() {
            // A suffix host is syntactically VALID (never matches an allowlist by prefix — the
            // comparison is exact-equality on the normalized origin, covered by evaluate tests).
            assertEquals(
                "https://station.lab.example.evil.com",
                normalizeOrigin("https://station.lab.example.evil.com"),
            )
            assertNull(normalizeOrigin("https://station.lab exemple"))
        }

        @Test
        fun `rejects percent encoding and non ascii hosts`() {
            assertNull(normalizeOrigin("https://st%61tion.lab.example"))
            assertNull(normalizeOrigin("https://stätion.lab.example"))
        }

        @Test
        fun `rejects schemes other than http and https`() {
            assertNull(normalizeOrigin("ftp://station.lab.example"))
            assertNull(normalizeOrigin("file:///etc/passwd"))
            assertNull(normalizeOrigin("chrome-extension://abc"))
        }

        @Test
        fun `rejects invalid ports`() {
            assertNull(normalizeOrigin("https://station.lab.example:0"))
            assertNull(normalizeOrigin("https://station.lab.example:65536"))
            assertNull(normalizeOrigin("https://station.lab.example:8a"))
            assertNull(normalizeOrigin("https://station.lab.example:"))
        }

        @Test
        fun `rejects empty oversized and scheme-less input`() {
            assertNull(normalizeOrigin(""))
            assertNull(normalizeOrigin(" ".repeat(1025)))
            assertNull(normalizeOrigin("station.lab.example"))
            assertNull(normalizeOrigin("//station.lab.example"))
        }
    }

    @Nested
    @DisplayName("parseAuthority")
    inner class ParseAuthorityTests {
        @Test
        fun `parses plain host without port`() {
            assertEquals(
                ParsedAuthority(host = "station.lab.example", port = null),
                parseAuthority("station.lab.example"),
            )
        }

        @Test
        fun `parses host with explicit port`() {
            assertEquals(
                ParsedAuthority(host = "station.lab.example", port = 8443),
                parseAuthority("station.lab.example:8443"),
            )
        }

        @Test
        fun `canonicalizes bracketed ipv6 with port`() {
            assertEquals(ParsedAuthority(host = "[::1]", port = 8443), parseAuthority("[::1]:8443"))
            assertEquals(ParsedAuthority(host = "[::1]", port = null), parseAuthority("[::1]"))
        }

        @Test
        fun `canonicalizes ipv4 mapped ipv6`() {
            assertEquals(
                ParsedAuthority(host = "[::ffff:127.0.0.1]", port = null),
                parseAuthority("[::ffff:127.0.0.1]"),
            )
        }

        @Test
        fun `lowercases host and strips trailing dot`() {
            assertEquals(
                ParsedAuthority(host = "station.lab.example", port = null),
                parseAuthority("Station.Lab.Example."),
            )
        }

        @Test
        fun `rejects unbracketed bare ipv6`() {
            assertNull(parseAuthority("::1"))
            assertNull(parseAuthority("::ffff:127.0.0.1"))
        }

        @Test
        fun `rejects malformed bracketed hosts`() {
            assertNull(parseAuthority("[::1"))
            assertNull(parseAuthority("[::1]:"))
            assertNull(parseAuthority("[::1]:0"))
            assertNull(parseAuthority("[::1]:99999"))
        }

        @Test
        fun `rejects invalid plain-host ports`() {
            assertNull(parseAuthority("station.lab.example:0"))
            assertNull(parseAuthority("station.lab.example:65536"))
            assertNull(parseAuthority("station.lab.example:8a"))
        }

        @Test
        fun `rejects whitespace userinfo and percent hosts`() {
            assertNull(parseAuthority("ev il.example"))
            assertNull(parseAuthority("user@station.lab.example"))
            assertNull(parseAuthority("st%61tion.lab.example"))
        }

        @Test
        fun `rejects oversized authority`() {
            assertNull(parseAuthority("a".repeat(1025)))
        }
    }

    @Nested
    @DisplayName("create fail fast")
    inner class CreateFailFastTests {
        @Test
        fun `hardened build throws on any origin`() {
            val exception =
                assertThrows<IllegalStateException> {
                    RequestOriginPolicy.create(isLabHardened = true, allowAnyOrigin = true)
                }
            assertTrue(exception.message!!.contains("refuse any-origin"))
        }

        @Test
        fun `hardened build throws on invalid allowlist entry`() {
            val invalid =
                listOf(
                    "*",
                    "null",
                    "https://station.lab.example/path",
                    "https://user@station.lab.example",
                    "ftp://station.lab.example",
                    "https://station.lab.example:0",
                    "https://station.lab.example:65536",
                    "https://stätion.lab.example",
                    "station.lab.example",
                    "",
                )
            invalid.forEach { entry ->
                val exception =
                    assertThrows<IllegalStateException> {
                        RequestOriginPolicy.create(isLabHardened = true, approvedOrigins = listOf(entry))
                    }
                assertTrue(exception.message!!.contains("invalid approved origin '$entry'"))
            }
        }

        @Test
        fun `hardened build accepts valid allowlist`() {
            val policy =
                RequestOriginPolicy.create(
                    isLabHardened = true,
                    approvedOrigins =
                        listOf(
                            approvedOrigin,
                            "http://localhost:8080",
                            "https://[::1]:8443",
                        ),
                )
            assertTrue(policy.isLabHardened)
            assertFalse(policy.anyOrigin)
            assertTrue(policy.isApprovedCrossOrigin(approvedOrigin))
            assertTrue(policy.isApprovedCrossOrigin("http://localhost:8080"))
            assertTrue(policy.isApprovedCrossOrigin("https://[::1]:8443"))
            assertFalse(policy.isApprovedCrossOrigin("https://evil.example"))
        }

        @Test
        fun `non hardened build passes through and drops allowlist`() {
            val policy =
                RequestOriginPolicy.create(
                    isLabHardened = false,
                    approvedOrigins = listOf(approvedOrigin),
                )
            assertTrue(policy.anyOrigin)
            assertFalse(policy.isLabHardened)
            // gms/foss CORS keeps anyHost() semantics: policy never denies anything.
            assertEquals(
                OriginDecision.Allowed,
                policy.evaluate(
                    RequestOriginFacts.of(
                        scheme = "http",
                        hostHeader = "attacker.example",
                        originHeader = "https://unapproved.example",
                    ),
                ),
            )
            assertFalse(policy.isApprovedCrossOrigin("http://localhost:8080"))
        }
    }

    @Nested
    @DisplayName("hardened evaluate: host gate")
    inner class HostGateTests {
        private val policy = RequestOriginPolicy.create(isLabHardened = true)

        @Test
        fun `absent origin on loopback host is allowed`() {
            val loopbackHosts =
                listOf("localhost", "localhost:8080", "127.0.0.1:8443", "[::1]", "[::1]:8080", "[::ffff:127.0.0.1]")
            loopbackHosts.forEach { host ->
                val decision = policy.evaluate(RequestOriginFacts.of(scheme = "http", hostHeader = host))
                assertTrue(decision is OriginDecision.Allowed, "host=$host decision=$decision")
            }
        }

        @Test
        fun `absent origin on configured allowlist host is allowed`() {
            val policy =
                RequestOriginPolicy.create(
                    isLabHardened = true,
                    approvedOrigins = listOf(approvedOrigin),
                )
            assertEquals(
                OriginDecision.Allowed,
                policy.evaluate(RequestOriginFacts.of(scheme = "https", hostHeader = "station.lab.example")),
            )
        }

        @Test
        fun `missing host header is denied`() {
            val decision =
                policy.evaluate(RequestOriginFacts(scheme = "http", hostHeader = null, originHeader = null))
            assertEquals(OriginDecision.Denied(RequestOriginPolicy.REASON_HOST_MISSING_OR_MALFORMED), decision)
        }

        @Test
        fun `unapproved host is denied even without origin`() {
            val decision =
                policy.evaluate(
                    RequestOriginFacts.of(scheme = "http", hostHeader = "attacker.rebind.example"),
                )
            assertEquals(OriginDecision.Denied(RequestOriginPolicy.REASON_HOST_NOT_APPROVED), decision)
        }

        @Test
        fun `malformed host headers are denied`() {
            listOf("ev il.example", "localhost:99999", "[::1", "[::1]:", "::1", "st%61tion.example").forEach { host ->
                val decision = policy.evaluate(RequestOriginFacts.of(scheme = "http", hostHeader = host))
                assertEquals(
                    OriginDecision.Denied(RequestOriginPolicy.REASON_HOST_MISSING_OR_MALFORMED),
                    decision,
                    "host=$host",
                )
            }
        }

        @Test
        fun `host gate runs before origin gate`() {
            // An approved Origin cannot rescue a request that arrived on an unapproved Host.
            val decision =
                policy.evaluate(
                    RequestOriginFacts.of(
                        scheme = "http",
                        hostHeader = "attacker.rebind.example",
                        originHeader = approvedOrigin,
                    ),
                )
            assertEquals(OriginDecision.Denied(RequestOriginPolicy.REASON_HOST_NOT_APPROVED), decision)
        }
    }

    @Nested
    @DisplayName("hardened evaluate: origin gate")
    inner class OriginGateTests {
        private val policy =
            RequestOriginPolicy.create(
                isLabHardened = true,
                approvedOrigins = listOf(approvedOrigin, "http://localhost:8080"),
            )

        @Test
        fun `same origin requests are allowed`() {
            listOf(
                Triple("http", "localhost:8080", "http://localhost:8080"),
                Triple("http", "localhost:80", "http://localhost"),
                Triple("http", "localhost", "http://localhost"),
                Triple("https", "127.0.0.1:8443", "https://127.0.0.1:8443"),
                Triple("https", "[::1]:8443", "https://[::1]:8443"),
            ).forEach { (scheme, host, origin) ->
                val decision =
                    policy.evaluate(RequestOriginFacts.of(scheme = scheme, hostHeader = host, originHeader = origin))
                assertTrue(decision is OriginDecision.Allowed, "origin=$origin decision=$decision")
            }
        }

        @Test
        fun `scheme mismatch is not same origin`() {
            // Same host+port but opposite scheme must NOT be treated as same-origin (no allowlist
            // entry for it here): only the exact https:// origin would be approved, so this denies.
            val policy =
                RequestOriginPolicy.create(
                    isLabHardened = true,
                    approvedOrigins = listOf("https://station.lab.example"),
                )
            assertEquals(
                OriginDecision.Denied(RequestOriginPolicy.REASON_ORIGIN_NOT_APPROVED),
                policy.evaluate(
                    RequestOriginFacts.of(
                        scheme = "https",
                        hostHeader = "localhost:8080",
                        originHeader = "http://localhost:8080",
                    ),
                ),
            )
            // Sanity: the same origin IS approved when it matches the allowlist entry exactly.
            val approved =
                RequestOriginPolicy.create(
                    isLabHardened = true,
                    approvedOrigins = listOf("http://localhost:8080"),
                )
            assertTrue(
                approved.evaluate(
                    RequestOriginFacts.of(
                        scheme = "https",
                        hostHeader = "localhost:8080",
                        originHeader = "http://localhost:8080",
                    ),
                ) is OriginDecision.Allowed,
                "scheme-mismatched origin allowed via explicit allowlist entry",
            )
        }

        @Test
        fun `unknown scheme falls back to origin allowlist`() {
            val allowed =
                policy.evaluate(
                    RequestOriginFacts.of(
                        scheme = "ws",
                        hostHeader = "localhost:8080",
                        originHeader = "http://localhost:8080",
                    ),
                )
            assertTrue(allowed is OriginDecision.Allowed, "approved origin over unknown scheme=$allowed")
            val denied =
                policy.evaluate(
                    RequestOriginFacts.of(
                        scheme = "ws",
                        hostHeader = "localhost:8080",
                        originHeader = "https://evil.example",
                    ),
                )
            assertEquals(OriginDecision.Denied(RequestOriginPolicy.REASON_ORIGIN_NOT_APPROVED), denied)
        }

        @Test
        fun `approved cross origin is allowed with normalization`() {
            assertEquals(
                OriginDecision.Allowed,
                policy.evaluate(
                    RequestOriginFacts.of(
                        scheme = "http",
                        hostHeader = "localhost:8080",
                        originHeader = "HTTPS://Station.Lab.Example:443",
                    ),
                ),
            )
        }

        @Test
        fun `wrong port origin is denied`() {
            assertEquals(
                OriginDecision.Denied(RequestOriginPolicy.REASON_ORIGIN_NOT_APPROVED),
                policy.evaluate(
                    RequestOriginFacts.of(
                        scheme = "http",
                        hostHeader = "localhost:8080",
                        originHeader = "https://station.lab.example:9000",
                    ),
                ),
            )
        }

        @Test
        fun `suffix path userinfo and percent origin tricks are denied`() {
            listOf(
                "https://station.lab.example.evil.com",
                "https://station.lab.example/path",
                "https://station.lab.example?q=1",
                "https://user@station.lab.example",
                "https://st%61tion.lab.example",
                "https://stätion.lab.example",
            ).forEach { origin ->
                val decision =
                    policy.evaluate(
                        RequestOriginFacts.of(scheme = "http", hostHeader = "localhost:8080", originHeader = origin),
                    )
                assertTrue(
                    decision is OriginDecision.Denied,
                    "origin=$origin should be denied, got $decision",
                )
            }
        }

        @Test
        fun `null and wildcard origins are denied`() {
            listOf("null", "*").forEach { origin ->
                val decision =
                    policy.evaluate(
                        RequestOriginFacts.of(scheme = "http", hostHeader = "localhost:8080", originHeader = origin),
                    )
                assertEquals(
                    OriginDecision.Denied(RequestOriginPolicy.REASON_ORIGIN_MALFORMED),
                    decision,
                    "origin=$origin",
                )
            }
        }

        @Test
        fun `trailing dot origin folds to approved`() {
            assertEquals(
                OriginDecision.Allowed,
                policy.evaluate(
                    RequestOriginFacts.of(
                        scheme = "http",
                        hostHeader = "localhost:8080",
                        originHeader = "https://station.lab.example.",
                    ),
                ),
            )
        }

        @Test
        fun `empty origin header is treated as absent`() {
            assertEquals(
                OriginDecision.Allowed,
                policy.evaluate(
                    RequestOriginFacts.of(scheme = "http", hostHeader = "localhost:8080", originHeader = "   "),
                ),
            )
        }
    }

    @Nested
    @DisplayName("isApprovedCrossOrigin")
    inner class IsApprovedCrossOriginTests {
        @Test
        fun `matches normalized approved origins`() {
            val policy = RequestOriginPolicy.create(isLabHardened = true, approvedOrigins = listOf(approvedOrigin))
            assertTrue(policy.isApprovedCrossOrigin(approvedOrigin))
            assertTrue(policy.isApprovedCrossOrigin("HTTPS://Station.Lab.Example:443"))
            assertTrue(policy.isApprovedCrossOrigin("https://station.lab.example."))
            assertFalse(policy.isApprovedCrossOrigin("https://station.lab.example:9000"))
            assertFalse(policy.isApprovedCrossOrigin("https://unapproved.example"))
            assertFalse(policy.isApprovedCrossOrigin("null"))
        }
    }

    @Nested
    @DisplayName("plugin config default")
    inner class PluginConfigTests {
        @Test
        fun `default policy mirrors build flavor`() {
            val config = McpRequestOriginPluginConfig()
            assertEquals(BuildConfig.LAB_HARDENED, config.policy.isLabHardened)
        }

        @Test
        fun `custom policy can be installed`() {
            val config = McpRequestOriginPluginConfig()
            config.policy = RequestOriginPolicy.create(isLabHardened = true, approvedOrigins = listOf(approvedOrigin))
            assertTrue(config.policy.isApprovedCrossOrigin(approvedOrigin))
        }
    }
}
