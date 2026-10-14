package com.danielealbano.androidremotecontrolmcp.services.adapters

/**
 * Typed adapter seam between the MCP service layer and a platform automation
 * framework.
 *
 * Implementations declare, as data (never through runtime introspection):
 * - which platform API levels they support,
 * - which Android permissions they require,
 * - an explicit schema for every action they can perform.
 *
 * Discovery is declarative: callers enumerate adapters and match actions via
 * [supports], which compares concrete action types, not method names or strings.
 */
interface FrameworkAdapter {
    /** Stable identifier, namespaced like a capability id (e.g. `"intent-framework"`). */
    val id: String

    /** Broad automation domain served by this adapter (e.g. `"intents"`). */
    val domain: String

    /** Inclusive range of Android API levels this adapter supports. */
    val supportedApiLevels: IntRange

    /** Android permissions required by every action of this adapter. */
    val requiredPermissions: List<String>

    /** Declarative schemas of all actions this adapter can perform. */
    val actionSchemas: List<AdapterActionSpec>

    /** Declarative discovery: true when this adapter performs [action]. */
    fun supports(action: AdapterAction): Boolean

    /**
     * Performs [action]. The adapter is responsible for refusing actions whose
     * features exceed the current platform API level with an
     * [AdapterOutcome.Rejected]; missing permissions are additionally enforced by
     * the registry before this call.
     */
    suspend fun dispatch(action: AdapterAction): AdapterOutcome
}
