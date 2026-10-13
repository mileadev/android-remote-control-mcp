package com.danielealbano.androidremotecontrolmcp.services.storage

import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress

/**
 * Pin the forbidden-range policy for [PublicInternetAddressPolicy]. String literals are
 * canonicalized by [InetAddress.getByName] without any DNS traffic.
 */
@DisplayName("DownloadAddressPolicy")
class DownloadAddressPolicyTest {
    private fun assertForbidden(address: InetAddress) {
        assertThrows<ForbiddenAddressException> { PublicInternetAddressPolicy.requireAllowed(address) }
    }

    private fun assertForbiddenLiteral(literal: String) {
        assertForbidden(InetAddress.getByName(literal))
    }

    @Test
    fun `forbids public internet addresses`() {
        listOf("8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111").forEach { literal ->
            val address = InetAddress.getByName(literal)
            assertDoesNotThrow { PublicInternetAddressPolicy.requireAllowed(address) }
        }
    }

    @Test
    fun `forbids loopback link-local and metadata ranges`() {
        listOf("127.0.0.1", "127.255.255.255", "169.254.169.254", "169.254.0.1", "fe80::1").forEach { literal ->
            assertForbiddenLiteral(literal)
        }
    }

    @Test
    fun `forbids rfc1918 private ranges`() {
        listOf("10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1").forEach { literal ->
            assertForbiddenLiteral(literal)
        }
        // Adjacent public ranges must stay allowed (boundary discipline).
        assertDoesNotThrow { PublicInternetAddressPolicy.requireAllowed(InetAddress.getByName("172.32.0.1")) }
        assertDoesNotThrow { PublicInternetAddressPolicy.requireAllowed(InetAddress.getByName("192.169.0.1")) }
        assertDoesNotThrow { PublicInternetAddressPolicy.requireAllowed(InetAddress.getByName("9.255.255.255")) }
    }

    @Test
    fun `forbids cgnat test-nets benchmark and reserved ranges`() {
        listOf(
            "100.64.0.1",
            "100.127.255.255",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.9",
            "198.18.0.1",
            "198.19.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ).forEach { literal -> assertForbiddenLiteral(literal) }
    }

    @Test
    fun `forbids this-network and unspecified addresses`() {
        listOf("0.0.0.0", "0.1.2.3").forEach { literal -> assertForbiddenLiteral(literal) }
        assertForbidden(InetAddress.getByName("::"))
    }

    @Test
    fun `forbids ipv6 multicast ula documentation and discard ranges`() {
        listOf("ff02::1", "fc00::1", "fd00::1", "2001:db8::5", "100::1").forEach { literal ->
            assertForbiddenLiteral(literal)
        }
    }

    @Test
    fun `forbids ipv4-mapped and ipv4-compatible ipv6 addresses`() {
        // Java canonicalizes ::ffff:a.b.c.d to Inet4Address, so the mapped form falls back
        // to the IPv4 rules; ::a.b.c.d stays Inet6Address and must be caught explicitly.
        assertForbidden(InetAddress.getByAddress(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1)))
        assertForbidden(InetAddress.getByAddress(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1)))
        assertForbiddenLiteral("::ffff:169.254.169.254")
        assertForbidden(InetAddress.getByAddress(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 1)))
    }

    @Test
    fun `forbidden exception is an UnknownHostException`() {
        assertThrows<java.net.UnknownHostException> {
            PublicInternetAddressPolicy.requireAllowed(InetAddress.getByName("127.0.0.1"))
        }
    }
}
