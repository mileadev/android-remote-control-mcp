package com.danielealbano.androidremotecontrolmcp.services.storage

import com.danielealbano.androidremotecontrolmcp.BuildConfig
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Shared SSL utility for the legacy permissive HTTPS path used by the SAF and MediaStore
 * download implementations behind the legacy `allowUnverifiedHttpsCerts` server flag.
 *
 * Hardened policy ([BuildConfig.LAB_HARDENED]) requires certificate and hostname validation
 * on every outgoing HTTPS connection: [configurePermissiveSsl] fails closed, throws and never
 * touches the connection, so callers surface a failed download and normal system trust applies.
 * The UI and ADB settings that could enable this path have been removed; gms and foss keep
 * the legacy opt-in only for backwards compatibility.
 */
object SslUtils {
    fun configurePermissiveSsl(connection: HttpsURLConnection) {
        if (BuildConfig.LAB_HARDENED) {
            throw IllegalStateException(
                "Permissive TLS is disabled by hardened policy: HTTPS certificate and hostname " +
                    "validation stays enabled and unverified certificates are never accepted.",
            )
        }
        val trustAllManager =
            @Suppress("CustomX509TrustManager")
            object : X509TrustManager {
                @Suppress("TrustAllX509TrustManager", "EmptyFunctionBlock")
                override fun checkClientTrusted(
                    chain: Array<X509Certificate>,
                    authType: String,
                ) { }

                @Suppress("TrustAllX509TrustManager", "EmptyFunctionBlock")
                override fun checkServerTrusted(
                    chain: Array<X509Certificate>,
                    authType: String,
                ) { }

                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())
        connection.sslSocketFactory = sslContext.socketFactory
        connection.hostnameVerifier = HostnameVerifier { _, _ -> true }
    }
}
