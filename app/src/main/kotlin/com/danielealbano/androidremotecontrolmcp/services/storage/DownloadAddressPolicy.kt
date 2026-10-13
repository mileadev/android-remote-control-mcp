package com.danielealbano.androidremotecontrolmcp.services.storage

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Thrown when a resolved download target address is forbidden by the [DownloadAddressPolicy].
 *
 * Extends [UnknownHostException] so it can be raised from an OkHttp [okhttp3.Dns]
 * implementation without breaking the resolution contract; OkHttp then aborts the
 * route before any socket is opened, which binds the allowlist to the actual
 * connection attempt (no separate resolve-then-connect window).
 */
public class ForbiddenAddressException(
    message: String,
    cause: Throwable? = null,
) : UnknownHostException(message)

/**
 * Policy deciding which resolved destination addresses a download may connect to.
 *
 * Implementations throw [ForbiddenAddressException] for any address that must never
 * be contacted through `download_from_url`.
 */
public fun interface DownloadAddressPolicy {
    fun requireAllowed(address: InetAddress)
}

/** A forbidden-address rule: a matcher over address bytes plus the human-readable reason. */
private typealias ForbiddenRule = Pair<(ByteArray) -> Boolean, String>

/**
 * Strict public-internet-only policy mandated by the download hardening spec (H-04).
 *
 * Rejects loopback, link-local (including the cloud metadata endpoint 169.254.169.254),
 * RFC 1918 private ranges, IPv6 ULA/multicast/link-local, IPv4-mapped and
 * IPv4-compatible IPv6 forms, CGNAT, broadcast/reserved and documentation/benchmark
 * networks.
 *
 * Organized as ordered rule tables ([IPV4_FORBIDDEN_RULES], [IPV6_FORBIDDEN_RULES]) so every
 * forbidden range is explicit and reviewable next to its deny reason.
 */
public object PublicInternetAddressPolicy : DownloadAddressPolicy {
    override fun requireAllowed(address: InetAddress) {
        val reason =
            when (address) {
                is Inet4Address -> ipv4ForbiddenReason(address.address)
                is Inet6Address -> ipv6ForbiddenReason(address.address)
                else -> null
            }
        if (reason != null) {
            throw ForbiddenAddressException("Download to $address is blocked ($reason)")
        }
    }

    private fun ipv4ForbiddenReason(octets: ByteArray): String? = firstMatchingReason(octets, IPV4_FORBIDDEN_RULES)

    private fun ipv6ForbiddenReason(bytes: ByteArray): String? =
        embeddedIpv4Reason(bytes) ?: firstMatchingReason(bytes, IPV6_FORBIDDEN_RULES)

    /**
     * `::ffff:a.b.c.d` (mapped) and `::a.b.c.d` (compatible) forms are decided by the
     * embedded IPv4 part through the IPv4 rule table.
     */
    private fun embeddedIpv4Reason(bytes: ByteArray): String? =
        when {
            isIpv4Embedded(bytes) || isIpv4Compatible(bytes) -> {
                firstMatchingReason(embeddedIpv4Bytes(bytes), IPV4_FORBIDDEN_RULES)
            }

            else -> {
                null
            }
        }

    private fun firstMatchingReason(
        value: ByteArray,
        rules: List<ForbiddenRule>,
    ): String? = rules.firstOrNull { (matches, _) -> matches(value) }?.second

    private fun embeddedIpv4Bytes(bytes: ByteArray): ByteArray {
        val ipv4 = ByteArray(IPV4_ADDRESS_LENGTH)
        bytes.copyInto(ipv4, 0, IPV6_LENGTH - IPV4_ADDRESS_LENGTH, IPV6_LENGTH)
        return ipv4
    }

    private fun isIpv4Embedded(bytes: ByteArray): Boolean =
        bytes.copyOfRange(0, IPV6_LENGTH - IPV4_EMBEDDED_PREFIX_LENGTH).all { it.toInt() == 0 } &&
            byteAt(bytes, IPV4_MAPPED_FIRST_BYTE_INDEX) == BYTE_MASK &&
            byteAt(bytes, IPV4_MAPPED_SECOND_BYTE_INDEX) == BYTE_MASK

    private fun isIpv4Compatible(bytes: ByteArray): Boolean =
        bytes.copyOfRange(0, IPV6_LENGTH - IPV4_ADDRESS_LENGTH).all { it.toInt() == 0 } &&
            !bytes.copyOfRange(IPV6_LENGTH - IPV4_ADDRESS_LENGTH, IPV6_LENGTH).all { it.toInt() == 0 }

    private val isUnspecifiedIpv6: (ByteArray) -> Boolean = { bytes: ByteArray -> bytes.all { it.toInt() == 0 } }

    private val isLoopbackIpv6: (ByteArray) -> Boolean = { bytes: ByteArray ->
        byteAt(bytes, IPV6_LENGTH - 1) == 1 && bytes.copyOfRange(0, IPV6_LENGTH - 1).all { it.toInt() == 0 }
    }

    private val isDocumentationIpv6: (ByteArray) -> Boolean = { bytes: ByteArray ->
        byteAt(bytes, 0) == IPV6_DOC_BYTE_0 &&
            byteAt(bytes, 1) == IPV6_DOC_BYTE_1 &&
            byteAt(bytes, 2) == IPV6_DOC_BYTE_2 &&
            byteAt(bytes, IPV6_DOC_LAST_BYTE_INDEX) == IPV6_DOC_BYTE_3
    }

    private val isDiscardOnlyIpv6: (ByteArray) -> Boolean = { bytes: ByteArray ->
        byteAt(bytes, 0) == 1 &&
            byteAt(bytes, 1) == 0 &&
            bytes.copyOfRange(2, IPV6_DISCARD_PREFIX_END).all { it.toInt() == 0 }
    }

    private fun byteAt(
        bytes: ByteArray,
        index: Int,
    ): Int = bytes[index].toInt() and BYTE_MASK

    // IPv4 range boundaries. Documented values, kept in one place for reviewability.
    const val BYTE_MASK = 0xFF
    const val LOOPBACK_FIRST_OCTET = 127
    const val LINK_LOCAL_FIRST_OCTET = 169
    const val LINK_LOCAL_SECOND_OCTET = 254
    const val PRIVATE_TEN_FIRST_OCTET = 10
    const val PRIVATE_172_FIRST_OCTET = 172
    val PRIVATE_172_SECOND_RANGE = 16..31
    const val PRIVATE_192_FIRST_OCTET = 192
    const val PRIVATE_192_SECOND_OCTET = 168
    const val CGNAT_FIRST_OCTET = 100
    val CGNAT_SECOND_RANGE = 64..127
    const val TEST_NET_192_FIRST_OCTET = 192
    const val TEST_NET_192_SECOND_OCTET = 0
    const val TEST_NET_192_THIRD_OCTET = 2
    const val TEST_NET_198_FIRST_OCTET = 198
    const val TEST_NET_198_SECOND_OCTET = 51
    const val TEST_NET_198_THIRD_OCTET = 100
    const val TEST_NET_203_FIRST_OCTET = 203
    const val TEST_NET_203_SECOND_OCTET = 0
    const val TEST_NET_203_THIRD_OCTET = 113
    const val BENCHMARK_FIRST_OCTET = 198
    val BENCHMARK_SECOND_RANGE = 18..19
    const val RESERVED_FIRST_OCTET = 240
    const val THIS_NETWORK_FIRST_OCTET = 0

    // IPv6 byte boundaries.
    const val IPV6_LENGTH = 16
    const val IPV4_ADDRESS_LENGTH = 4
    const val IPV4_EMBEDDED_PREFIX_LENGTH = 10
    const val IPV4_MAPPED_FIRST_BYTE_INDEX = 10
    const val IPV4_MAPPED_SECOND_BYTE_INDEX = 11
    const val IPV6_DOC_LAST_BYTE_INDEX = 3
    const val IPV6_DISCARD_PREFIX_END = 8
    const val IPV6_MULTICAST_FIRST_BYTE = 0xFF
    const val IPV6_LINK_LOCAL_FIRST_BYTE = 0xFE
    const val IPV6_LINK_LOCAL_MASK = 0xC0
    const val IPV6_LINK_LOCAL_TOP = 0x80
    val IPV6_ULA_FIRST_RANGE = 0xFC..0xFD
    const val IPV6_DOC_BYTE_0 = 0x20
    const val IPV6_DOC_BYTE_1 = 0x01
    const val IPV6_DOC_BYTE_2 = 0x0D
    const val IPV6_DOC_BYTE_3 = 0xB8

    private val IPV4_FORBIDDEN_RULES: List<ForbiddenRule> =
        listOf(
            { b: ByteArray -> byteAt(b, 0) == LOOPBACK_FIRST_OCTET } to "loopback network 127/8",
            { b: ByteArray ->
                byteAt(b, 0) == LINK_LOCAL_FIRST_OCTET && byteAt(b, 1) == LINK_LOCAL_SECOND_OCTET
            } to "link-local network 169.254/16 (includes cloud metadata endpoint)",
            { b: ByteArray -> byteAt(b, 0) == PRIVATE_TEN_FIRST_OCTET } to "private network 10/8",
            { b: ByteArray ->
                byteAt(b, 0) == PRIVATE_172_FIRST_OCTET && byteAt(b, 1) in PRIVATE_172_SECOND_RANGE
            } to "private network 172.16/12",
            { b: ByteArray ->
                byteAt(b, 0) == PRIVATE_192_FIRST_OCTET && byteAt(b, 1) == PRIVATE_192_SECOND_OCTET
            } to "private network 192.168/16",
            { b: ByteArray ->
                byteAt(b, 0) == CGNAT_FIRST_OCTET && byteAt(b, 1) in CGNAT_SECOND_RANGE
            } to "shared address space 100.64/10",
            { b: ByteArray ->
                byteAt(b, 0) == TEST_NET_192_FIRST_OCTET &&
                    byteAt(b, 1) == TEST_NET_192_SECOND_OCTET &&
                    byteAt(b, 2) == TEST_NET_192_THIRD_OCTET
            } to "documentation network 192.0.2/24",
            { b: ByteArray ->
                byteAt(b, 0) == TEST_NET_198_FIRST_OCTET &&
                    byteAt(b, 1) == TEST_NET_198_SECOND_OCTET &&
                    byteAt(b, 2) == TEST_NET_198_THIRD_OCTET
            } to "documentation network 198.51.100/24",
            { b: ByteArray ->
                byteAt(b, 0) == TEST_NET_203_FIRST_OCTET &&
                    byteAt(b, 1) == TEST_NET_203_SECOND_OCTET &&
                    byteAt(b, 2) == TEST_NET_203_THIRD_OCTET
            } to "documentation network 203.0.113/24",
            { b: ByteArray ->
                byteAt(b, 0) == BENCHMARK_FIRST_OCTET && byteAt(b, 1) in BENCHMARK_SECOND_RANGE
            } to "benchmarking network 198.18/15",
            { b: ByteArray -> byteAt(b, 0) >= RESERVED_FIRST_OCTET } to "reserved network 240/4",
            { b: ByteArray -> byteAt(b, 0) == THIS_NETWORK_FIRST_OCTET } to "this network 0/8",
        )

    private val IPV6_FORBIDDEN_RULES: List<ForbiddenRule> =
        listOf(
            isUnspecifiedIpv6 to "unspecified address ::",
            isLoopbackIpv6 to "loopback address ::1",
            isDocumentationIpv6 to "documentation network 2001:db8::/32",
            { b: ByteArray -> byteAt(b, 0) == IPV6_MULTICAST_FIRST_BYTE } to "multicast network ff00::/8",
            { b: ByteArray ->
                byteAt(b, 0) == IPV6_LINK_LOCAL_FIRST_BYTE &&
                    (byteAt(b, 1) and IPV6_LINK_LOCAL_MASK) == IPV6_LINK_LOCAL_TOP
            } to "link-local network fe80::/10",
            { b: ByteArray -> byteAt(b, 0) in IPV6_ULA_FIRST_RANGE } to "unique local address fc00::/7",
            isDiscardOnlyIpv6 to "discard-only network 100::/64",
        )
}
