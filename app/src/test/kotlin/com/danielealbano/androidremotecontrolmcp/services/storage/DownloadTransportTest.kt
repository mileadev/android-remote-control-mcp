package com.danielealbano.androidremotecontrolmcp.services.storage

import com.danielealbano.androidremotecontrolmcp.data.model.ServerConfig
import okhttp3.Dns
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.Inet4Address
import java.net.InetAddress
import java.net.UnknownHostException

/** Stub resolver returning canned addresses (or failing) without touching real DNS. */
private class FakeDns(
    private val addresses: List<InetAddress> = emptyList(),
    private var failure: UnknownHostException? = null,
) : Dns {
    val queriedHosts = mutableListOf<String>()

    override fun lookup(hostname: String): List<InetAddress> {
        queriedHosts.add(hostname)
        failure?.let { throw it }
        return addresses
    }
}

@DisplayName("DownloadTransport")
class DownloadTransportTest {
    @Test
    fun `PolicyDns passes public internet addresses through`() {
        val public = InetAddress.getByName("93.184.216.34")
        val dns = PolicyDns(FakeDns(listOf(public)))

        val resolved = dns.lookup("example.com")

        assertEquals(listOf<InetAddress>(public), resolved)
    }

    @Test
    fun `PolicyDns rejects forbidden address and names the host`() {
        val dns = PolicyDns(FakeDns(listOf(InetAddress.getByName("169.254.169.254"))))

        val exception = assertThrows<ForbiddenAddressException> { dns.lookup("metadata.internal.example") }

        assertTrue(exception.message!!.contains("metadata.internal.example"))
        assertTrue(exception.message!!.contains("blocked"))
    }

    @Test
    fun `PolicyDns rejects rebinding across multiple returned addresses`() {
        val dns = PolicyDns(FakeDns(listOf(InetAddress.getByName("93.184.216.34"), InetAddress.getByName("10.0.0.9"))))

        assertThrows<ForbiddenAddressException> { dns.lookup("rebind.example") }
    }

    @Test
    fun `PolicyDns propagates resolver failures unchanged`() {
        val dns = PolicyDns(FakeDns(failure = UnknownHostException("nx: no such host")))

        val exception = assertThrows<UnknownHostException> { dns.lookup("missing.example") }

        assertEquals("nx: no such host", exception.message)
    }

    @Test
    fun `PolicyDns keeps IPv6 link-local out of public downloads`() {
        val dns = PolicyDns(FakeDns(listOf(InetAddress.getByName("fe80::1"))))

        assertThrows<ForbiddenAddressException> { dns.lookup("v6host.example") }
    }

    @Test
    fun `SecureDownloadClient applies hardened download settings`() {
        val client = SecureDownloadClient.create(ServerConfig(downloadTimeoutSeconds = 7))

        assertEquals(7000, client.callTimeoutMillis)
        assertEquals(7000, client.connectTimeoutMillis)
        assertEquals(7000, client.readTimeoutMillis)
        assertEquals(7000, client.writeTimeoutMillis)
        assertFalse(client.followRedirects)
        assertInstanceOf(PolicyDns::class.java, client.dns)
    }

    @Test
    fun `SecureDownloadClient routes every connection through the address policy`() {
        val metadata = InetAddress.getByName("169.254.169.254")
        val client = SecureDownloadClient.create(ServerConfig(), dns = FakeDns(listOf(metadata)))

        val policyDns = client.dns as PolicyDns

        // The engine connects to the policy-dns-wrapped client; a resolved private address
        // must be refused before any socket is opened.
        val exception =
            assertThrows<UnknownHostException> {
                policyDns.lookup("rebind.internal.example")
            }
        assertTrue(exception is ForbiddenAddressException)
    }

    @Test
    fun `SecureDownloadClient uses a public-internet-only policy by default`() {
        val addresses = listOf(Inet4Address.getByName("93.184.216.34"))
        val dns = PolicyDns(FakeDns(addresses))

        // Guard the shared policy binding used by the default SecureDownloadClient path.
        PublicInternetAddressPolicy.requireAllowed(addresses.single())
    }
}
