package com.danielealbano.androidremotecontrolmcp.services.adapters

/**
 * Typed field types for adapter action schemas.
 *
 * Every input and output field of an adapter action is declared with an
 * [AdapterFieldType] so callers get compile-time-checked data exchange instead of
 * loosely typed maps.
 */
enum class AdapterFieldType {
    /** Non-empty string. */
    STRING,

    /** String that may be absent or null. */
    STRING_NULLABLE,

    /** 32-bit integer. */
    INT,

    /** Boolean. */
    BOOLEAN,

    /** List of strings. */
    STRING_LIST,

    /** Map of string keys to caller-provided values. */
    STRING_VALUE_MAP,

    /** Single value restricted by [AdapterActionSpec.enumValues]. */
    ENUM,
}

/**
 * Declarative schema of a single adapter action.
 *
 * @property actionId Stable identifier of the action, namespaced by adapter domain.
 * @property description Human-readable summary of what the action performs.
 * @property inputFields Typed input fields of the action.
 * @property outputFields Typed output fields produced by the action.
 * @property minApiLevel Minimum Android API level on which the action is callable.
 * @property requiredPermissions Android permissions required on top of the adapter-level ones.
 * @property enumValues Allowed values per ENUM-typed field.
 */
data class AdapterActionSpec(
    val actionId: String,
    val description: String,
    val inputFields: Map<String, AdapterFieldType>,
    val outputFields: Map<String, AdapterFieldType>,
    val minApiLevel: Int,
    val requiredPermissions: List<String> = emptyList(),
    val enumValues: Map<String, List<String>> = emptyMap(),
)

/**
 * Typed action handed to a [FrameworkAdapter]. Actions carry no stringly-typed
 * method names or untyped payloads; the concrete data type selects the operation.
 *
 * [AdapterAction] is intentionally not sealed: test doubles and additional
 * adapters may declare their own actions, and dispatch discovery is explicit
 * ([FrameworkAdapter.supports]) rather than sealed-type exhaustive.
 */
interface AdapterAction {
    val actionId: String
}

/**
 * Typed outcome of a gated adapter dispatch.
 */
sealed interface AdapterOutcome {
    /** The action completed successfully. */
    data class Completed(
        val detail: String,
    ) : AdapterOutcome

    /** The adapter executed the action but failed for a typed, reportable reason. */
    data class Failed(
        val message: String,
    ) : AdapterOutcome

    /** The action was refused before execution by a gate (version or permissions). */
    data class Rejected(
        val rejection: AdapterRejection,
    ) : AdapterOutcome
}

/**
 * Typed refusal reasons produced by version and permission gates.
 */
sealed interface AdapterRejection {
    /** The adapter itself does not support the current platform API level. */
    data class UnsupportedApiLevel(
        val adapterId: String,
        val supportedApiLevels: IntRange,
        val actualApiLevel: Int,
    ) : AdapterRejection

    /** The action id is not declared by any reachable adapter. */
    data class UnknownAction(
        val actionId: String,
        val supportedActionIds: List<String>,
    ) : AdapterRejection

    /** The action exists but needs a newer platform API level. */
    data class ActionRequiresNewerApi(
        val actionId: String,
        val minApiLevel: Int,
        val actualApiLevel: Int,
    ) : AdapterRejection

    /** A feature used by the action (e.g. a flag) needs a newer platform API level. */
    data class FeatureRequiresNewerApi(
        val feature: String,
        val minApiLevel: Int,
        val actualApiLevel: Int,
    ) : AdapterRejection

    /** Required Android permissions are not granted. */
    data class MissingPermissions(
        val permissions: List<String>,
    ) : AdapterRejection
}

/**
 * Deterministic, user-facing description of a rejection. Messages are safe to
 * surface to MCP clients: they never embed platform internals.
 */
fun AdapterRejection.describe(): String =
    when (this) {
        is AdapterRejection.UnsupportedApiLevel -> {
            "Adapter '$adapterId' does not support API level $actualApiLevel " +
                "(supported: ${supportedApiLevels.first}..${supportedApiLevels.last})"
        }

        is AdapterRejection.UnknownAction -> {
            "Unknown action '$actionId'. Supported actions: ${supportedActionIds.sorted()}"
        }

        is AdapterRejection.ActionRequiresNewerApi -> {
            "Action '$actionId' requires API level $minApiLevel (device API level: $actualApiLevel)"
        }

        is AdapterRejection.FeatureRequiresNewerApi -> {
            "'$feature' requires API level $minApiLevel (device API level: $actualApiLevel)"
        }

        is AdapterRejection.MissingPermissions -> {
            "Missing required permissions: ${permissions.sorted().joinToString(", ")}"
        }
    }
