package com.danielealbano.androidremotecontrolmcp.e2e

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress

/**
 * Minimal host-side HTTP server for download_from_url E2E tests.
 * Bound on 0.0.0.0:[FIXTURE_HTTP_PORT] (the port is exposed to the container
 * before it starts).
 *
 * Endpoints:
 * - GET /fixture.txt   -> 200, body [FIXTURE_CONTENT], Content-Type text/plain
 *
 * Plain HTTP on purpose: the hardened download policy must refuse this server even
 * though the container can reach it (see E2EStorageToolsTest rows 23-27).
 */
class FixtureHttpServer {
    private var server: HttpServer? = null

    fun start() {
        val s = HttpServer.create(InetSocketAddress("0.0.0.0", FIXTURE_HTTP_PORT), 0)
        s.createContext("/fixture.txt") { exchange ->
            val body = FIXTURE_CONTENT.toByteArray()
            exchange.responseHeaders.add("Content-Type", "text/plain")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        s.start()
        server = s
    }

    fun stop() {
        server?.stop(0)
        server = null
    }

    /**
     * Base URL as reachable FROM INSIDE the container.
     *
     * Verified mechanism on redroid 13 and 14 (plan empirical procedure 2): the primary
     * `host.testcontainers.internal` name is NOT resolvable inside redroid's Android
     * runtime (Android's resolver does not see the Testcontainers hosts entry), so the
     * container's default-gateway IP — the host on podman's bridge — is used instead.
     */
    fun containerReachableBaseUrl(): String {
        // Android uses policy routing, so the main `ip route` table has no `default` line;
        // `ip route get <external ip>` resolves through the policy tables and prints
        // "<ip> via <gateway> dev ...".
        val out = AndroidContainerSetup.execAdb("shell", "ip", "route", "get", "1.1.1.1")
        val tokens = out.split(Regex("\\s+"))
        val gateway = tokens[tokens.indexOf("via") + 1]
        return "http://$gateway:$FIXTURE_HTTP_PORT"
    }

    companion object {
        /** Fixed host port, exposed to the container by SharedAndroidContainer before start. */
        const val FIXTURE_HTTP_PORT = 18923
        const val FIXTURE_CONTENT = "e2e-download-fixture-content"
    }
}
