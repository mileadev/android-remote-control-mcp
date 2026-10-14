package com.danielealbano.androidremotecontrolmcp.testutil

import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.data.model.ToolPermissionsConfig
import com.danielealbano.androidremotecontrolmcp.mcp.tools.CapabilityCatalog
import com.danielealbano.androidremotecontrolmcp.mcp.tools.DownloadFromUrlHandler
import com.danielealbano.androidremotecontrolmcp.mcp.tools.McpToolUtils

/**
 * The MCP tool surface a test expects the server to expose, derived from production sources
 * instead of a hand-maintained copy of the roster.
 *
 * The names come from [CapabilityCatalog.deviceCatalog] — the same document the server gates
 * dispatch on at startup and per call — filtered by the compile-time flavour gate and by the
 * stored tool permissions. A tool dropped or renamed in production registration, or dropped from
 * the catalog, therefore fails every test that asserts against this expectation; a hand-copied
 * literal list cannot detect that drift, because it is a copy of the thing it should mirror.
 *
 * Residual gap (named rather than hidden): the *sequence* of production registration calls inside
 * `McpServerService.registerAllTools` is mirrored, function for function, by
 * `McpIntegrationTestHelper.registerAllTools`, which invokes the production `registerXxxTools`
 * entry points with mocked collaborators. A whole bundle added to one list but not the other is
 * not detected; the catalog-integrity test in `CapabilityCatalogSchemaTest` detects every
 * difference in the *tools* those calls produce. Closing the bundling gap would mean extracting
 * production registration into a function shared by the service and the test helper, but the two
 * collaborator sets are real services versus mockk mocks, so the extraction is not small.
 */
object ExpectedToolSurface {
    /**
     * Catalog entries the current flavour never registers: hardened builds drop the download tool
     * (the `!BuildConfig.LAB_HARDENED` guard in `registerFileTools`). The name is read from the
     * production handler, so renaming the tool there keeps this in sync.
     */
    val flavourGatedOff: Set<String> =
        if (BuildConfig.LAB_HARDENED) setOf(DownloadFromUrlHandler.TOOL_NAME) else emptySet()

    /** Every tool name the catalog lists, regardless of flavour or stored permissions. */
    fun catalogToolNames(): Set<String> = CapabilityCatalog.deviceCatalog().toolNames

    /** Un-prefixed tool names this flavour and [perms] are expected to expose. */
    fun toolNames(perms: ToolPermissionsConfig = ToolPermissionsConfig()): Set<String> =
        catalogToolNames()
            .filterNot { it in flavourGatedOff }
            .filter { perms.isToolEnabled(it) }
            .toSet()

    /** The expected live surface as the MCP server exposes it, production name prefix included. */
    fun prefixedToolNames(
        perms: ToolPermissionsConfig = ToolPermissionsConfig(),
        deviceSlug: String = "",
    ): Set<String> = withPrefix(toolNames(perms), deviceSlug)

    /** Applies the production tool-name prefix for [deviceSlug] to every name in [toolNames]. */
    fun withPrefix(
        toolNames: Collection<String>,
        deviceSlug: String = "",
    ): Set<String> {
        val prefix = McpToolUtils.buildToolNamePrefix(deviceSlug)
        return toolNames.mapTo(linkedSetOf()) { prefix + it }
    }
}
