package com.danielealbano.androidremotecontrolmcp.services.storage

import com.danielealbano.androidremotecontrolmcp.BuildConfig
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.URL
import javax.net.ssl.HttpsURLConnection

@DisplayName("TLS policy")
class TlsPolicyTest {
    @Test
    fun `permissive TLS engages only outside hardened builds`() {
        val connection =
            URL("https://androidremotecontrolmcp.example").openConnection() as HttpsURLConnection

        if (BuildConfig.LAB_HARDENED) {
            // Hardened policy fails closed: permissive TLS must throw and leave the connection
            // untouched so system certificate and hostname validation stays enforced.
            val exception =
                assertThrows<IllegalStateException> { SslUtils.configurePermissiveSsl(connection) }
            assertTrue(exception.message!!.contains("certificate and hostname validation"))
            assertSame(HttpsURLConnection.getDefaultSSLSocketFactory(), connection.sslSocketFactory)
            assertSame(HttpsURLConnection.getDefaultHostnameVerifier(), connection.hostnameVerifier)
        } else {
            // gms/foss compatibility: the legacy opt-in still configures permissive TLS that
            // accepts any certificate chain and any hostname.
            SslUtils.configurePermissiveSsl(connection)

            assertNotNull(connection.sslSocketFactory)
            assertNotNull(connection.hostnameVerifier)
            assertTrue(connection.hostnameVerifier!!.verify("untrusted.example", null))
        }
    }
}
