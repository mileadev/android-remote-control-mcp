package com.danielealbano.androidremotecontrolmcp.data.model

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

private const val POLICY_SCHEMA_VERSION = 1
private const val KEY_SCHEMA_VERSION = "schemaVersion"
private const val KEY_ALLOWED_TOOL_IDS = "allowedToolIds"
private const val KEY_DISABLED_TOOLS = "disabledTools"
private const val KEY_DISABLED_PARAMS = "disabledParams"

/**
 * Tool-level and parameter-level capability policy persisted in app settings.
 *
 * Two document formats exist:
 * - Upstream denylist: `{"disabledTools":[...],"disabledParams":{...}}`; unknown tools
 *   remain enabled and missing/corrupt JSON falls back to all-enabled.
 * - Hardened allowlist (labHardened): a versioned policy document
 *   `{"schemaVersion":1,"allowedToolIds":[...],"disabledParams":{...},"disabledTools":[...]}`;
 *   a non-null [allowedToolIds] selects these semantics so every tool not explicitly
 *   listed is denied. Hardened parsing (see [fromJsonForPolicy]) resolves missing,
 *   corrupt or partial documents to [DENY_ALL] (fail closed) instead of falling back
 *   open.
 *
 * [disabledTools] is ANDed with the allowlist so runtime permission gating
 * (`OptionalToolPermissions.effectivePermissions`) keeps working unchanged: copies that
 * add permission-blocked tools to [disabledTools] deny them even when allowlisted.
 */
data class ToolPermissionsConfig(
    val disabledTools: Set<String> = emptySet(),
    val disabledParams: Map<String, Set<String>> = emptyMap(),
    val allowedToolIds: Set<String>? = null,
) {
    /** Persistence policy applied by [Companion.fromJsonForPolicy]. */
    enum class PolicyMode { PERMISSIVE_DEFAULT, FAIL_CLOSED }

    /**
     * True when [toolName] may execute at all: explicitly allowlisted when the document
     * carries a hardened allowlist, and never listed in [disabledTools].
     */
    fun isToolEnabled(toolName: String): Boolean {
        val allowlisted = allowedToolIds == null || toolName in allowedToolIds
        return allowlisted && toolName !in disabledTools
    }

    /**
     * True when [paramName] of [toolName] is not disabled. When the document carries a
     * hardened allowlist, parameters of tools that the policy denies are also denied.
     */
    fun isParamEnabled(
        toolName: String,
        paramName: String,
    ): Boolean =
        (allowedToolIds == null || isToolEnabled(toolName)) &&
            paramName !in (disabledParams[toolName] ?: emptySet())

    /** Serializes in the upstream denylist format or the versioned hardened format. */
    fun toJson(): String =
        buildJsonObject {
            if (allowedToolIds == null) {
                put(KEY_DISABLED_TOOLS, stringArrayJson(disabledTools))
                put(KEY_DISABLED_PARAMS, disabledParamsJson())
            } else {
                put(KEY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION)
                put(KEY_ALLOWED_TOOL_IDS, stringArrayJson(allowedToolIds))
                put(KEY_DISABLED_PARAMS, disabledParamsJson())
                put(KEY_DISABLED_TOOLS, stringArrayJson(disabledTools))
            }
        }.toString()

    private fun stringArrayJson(values: Set<String>) = buildJsonArray { values.forEach { add(it) } }

    private fun disabledParamsJson(): JsonObject =
        buildJsonObject {
            disabledParams.forEach { (tool, params) ->
                put(tool, buildJsonArray { params.forEach { add(it) } })
            }
        }

    companion object {
        /**
         * Fail-closed fallback for hardened policy parsing: an empty allowlist denies
         * every tool (and, via [isParamEnabled], every parameter) until the operator
         * explicitly allowlists tools.
         */
        val DENY_ALL = ToolPermissionsConfig(allowedToolIds = emptySet())

        fun fromJson(json: String): ToolPermissionsConfig? =
            try {
                val obj = Json.parseToJsonElement(json).jsonObject
                val disabledTools =
                    obj["disabledTools"]
                        ?.jsonArray
                        ?.mapNotNull { it.jsonPrimitive.contentOrNull }
                        ?.toSet()
                        ?: emptySet()
                val disabledParams =
                    obj["disabledParams"]
                        ?.jsonObject
                        ?.mapValues { (_, v) ->
                            v.jsonArray.mapNotNull { it.jsonPrimitive.contentOrNull }.toSet()
                        }
                        ?: emptyMap()
                ToolPermissionsConfig(disabledTools = disabledTools, disabledParams = disabledParams)
            } catch (_: kotlinx.serialization.SerializationException) {
                null
            } catch (_: IllegalArgumentException) {
                null
            } catch (_: IllegalStateException) {
                null
            }

        fun fromJsonOrDefault(json: String?): ToolPermissionsConfig =
            if (json == null) ToolPermissionsConfig() else fromJson(json) ?: ToolPermissionsConfig()

        /**
         * Parses [json] under the persistence policy of [mode].
         *
         * [PolicyMode.PERMISSIVE_DEFAULT] keeps the upstream fallback ([fromJsonOrDefault]):
         * null or unparseable JSON falls back to the all-tools-enabled configuration.
         *
         * [PolicyMode.FAIL_CLOSED] requires the versioned hardened policy document; any
         * parse failure, missing or malformed field, unexpected key, or unknown schema
         * version resolves to [DENY_ALL] instead of falling back open. Upstream-format
         * documents (no [KEY_SCHEMA_VERSION]) also resolve to [DENY_ALL], so migrated or
         * hand-copied persisted settings never silently re-enable a tool set.
         */
        fun fromJsonForPolicy(
            json: String?,
            mode: PolicyMode,
        ): ToolPermissionsConfig =
            when (mode) {
                PolicyMode.PERMISSIVE_DEFAULT -> {
                    fromJsonOrDefault(json)
                }

                PolicyMode.FAIL_CLOSED -> {
                    if (json == null) {
                        DENY_ALL
                    } else {
                        parsePolicyDocument(json)
                    }
                }
            }

        private fun parsePolicyDocument(json: String): ToolPermissionsConfig =
            try {
                validatePolicyDocument(Json.parseToJsonElement(json).jsonObject)
            } catch (_: kotlinx.serialization.SerializationException) {
                DENY_ALL
            } catch (_: IllegalArgumentException) {
                DENY_ALL
            } catch (_: IllegalStateException) {
                DENY_ALL
            }

        private fun validatePolicyDocument(obj: JsonObject): ToolPermissionsConfig {
            val knownKeys =
                setOf(
                    KEY_SCHEMA_VERSION,
                    KEY_ALLOWED_TOOL_IDS,
                    KEY_DISABLED_PARAMS,
                    KEY_DISABLED_TOOLS,
                )
            // An unrecognized key means the stored document is not a policy revision.
            require(obj.keys.all { it in knownKeys })

            val versionPrimitive = requireNotNull(obj[KEY_SCHEMA_VERSION]?.jsonPrimitive)
            require(versionPrimitive.content.toIntOrNull() == POLICY_SCHEMA_VERSION)

            val allowedToolIds = requireStringArray(obj[KEY_ALLOWED_TOOL_IDS])
            val disabledParams = requireStringSetMap(obj[KEY_DISABLED_PARAMS])
            val disabledTools = obj[KEY_DISABLED_TOOLS]?.let { requireStringArray(it) } ?: emptySet()
            return ToolPermissionsConfig(
                disabledTools = disabledTools,
                disabledParams = disabledParams,
                allowedToolIds = allowedToolIds,
            )
        }

        private fun requireStringArray(element: JsonElement?): Set<String> {
            val array = element as? JsonArray
            requireNotNull(array)
            return array
                .map { item ->
                    val primitive = requireNotNull(item as? JsonPrimitive)
                    require(primitive.isString)
                    primitive.content
                }.toSet()
        }

        private fun requireStringSetMap(element: JsonElement?): Map<String, Set<String>> {
            val obj = element as? JsonObject
            requireNotNull(obj)
            return obj.mapValues { (_, value) -> requireStringArray(value) }
        }
    }
}
