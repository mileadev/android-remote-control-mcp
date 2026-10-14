package com.danielealbano.androidremotecontrolmcp.mcp.tools

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.security.MessageDigest

/**
 * Privilege tiers for registered capabilities (04-CONTROL-PLANE-CONTRACT.md privilege model).
 *
 * [rank] orders tiers lowest→highest risk: a gate with a provisioned ceiling admits entries at
 * or below that ceiling only. T3_MANAGED/T4_USERDEBUG/T5_PLATFORM are never present in the
 * device tool catalog; on hardened builds the provisioned ceiling defaults to [T2_TEST] so
 * managed-grade capabilities stay OFF unless a maintainer explicitly provisions them.
 */
enum class PrivilegeTier(
    val wireName: String,
    val rank: Int,
) {
    T1_APP(wireName = "T1_APP", rank = 1),
    T2_TEST(wireName = "T2_TEST", rank = 2),
    T3_MANAGED(wireName = "T3_MANAGED", rank = 3),
    T4_USERDEBUG(wireName = "T4_USERDEBUG", rank = 4),
    T5_PLATFORM(wireName = "T5_PLATFORM", rank = 5),
    ;

    companion object {
        private val BY_WIRE_NAME: Map<String, PrivilegeTier> =
            PrivilegeTier.entries.associateBy { it.wireName }

        /** The [PrivilegeTier] for a contract wire value, or null when unknown. */
        fun fromWireName(name: String): PrivilegeTier? = BY_WIRE_NAME[name]
    }
}

/** Risk label for a capability (contract `risk` field). */
enum class CapabilityRisk(
    val wireName: String,
) {
    READ_ONLY(wireName = "read_only"),
    MUTATING(wireName = "mutating"),
    DESTRUCTIVE(wireName = "destructive"),
    NETWORK(wireName = "network"),
    ;

    companion object {
        private val BY_WIRE_NAME: Map<String, CapabilityRisk> =
            CapabilityRisk.entries.associateBy { it.wireName }

        /** The [CapabilityRisk] for a contract wire value, or null when unknown. */
        fun fromWireName(name: String): CapabilityRisk? = BY_WIRE_NAME[name]
    }
}

/** Per-device verification status for a capability (contract `device_status` field). */
enum class DeviceCapabilityStatus(
    val wireName: String,
) {
    VERIFIED(wireName = "verified"),
    NOT_TESTED(wireName = "not_tested"),
    ;

    companion object {
        private val BY_WIRE_NAME: Map<String, DeviceCapabilityStatus> =
            DeviceCapabilityStatus.entries.associateBy { it.wireName }

        /** The [DeviceCapabilityStatus] for a contract wire value, or null when unknown. */
        fun fromWireName(name: String): DeviceCapabilityStatus? = BY_WIRE_NAME[name]
    }
}

/**
 * Contract `verification` object: test evidence for a VERIFIED capability. All fields are
 * all-or-nothing — a [CapabilityEntry] that claims VERIFIED status must carry all three.
 */
data class CapabilityVerification(
    val testId: String,
    val apkSha256: String,
    val timestampUtc: String,
)

/**
 * One catalog entry for a registered MCP tool.
 *
 * The wire shape (see [CapabilityEntry.wireObject]) follows the 04-CONTROL-PLANE-CONTRACT.md
 * registry-entry schema exactly (api_id/adapter_id/platform/min-max_api_level/privilege_tier/
 * required_permissions/hardware_features/argument_schema_revision/risk/device_status/
 * verification). [toolName] is the device-side dispatch key (the un-prefixed MCP tool name);
 * it stays out of the wire object so device and station share one byte-identical schema.
 *
 * Construction is fail-fast: every field is validated typewise at build time, so a catalog
 * entry that violates the schema can never be registered.
 */
data class CapabilityEntry(
    val toolName: String,
    val apiId: String,
    val adapterId: String,
    val privilegeTier: PrivilegeTier,
    val risk: CapabilityRisk,
    val platform: String = DEFAULT_PLATFORM,
    val minApiLevel: Int = DEFAULT_MIN_API_LEVEL,
    val maxApiLevel: Int? = null,
    val requiredPermissions: List<String> = emptyList(),
    val hardwareFeatures: List<String> = emptyList(),
    val argumentSchemaRevision: String = DEFAULT_ARGUMENT_SCHEMA_REVISION,
    val deviceStatus: DeviceCapabilityStatus = DeviceCapabilityStatus.NOT_TESTED,
    val verification: CapabilityVerification? = null,
) {
    init {
        require(TOOL_NAME_PATTERN.matches(toolName)) {
            "capability entry: tool_name '$toolName' must match ^[a-z][a-z0-9_]{2,63}$"
        }
        require(API_ID_PATTERN.matches(apiId)) {
            "capability entry: api_id '$apiId' must match ^android\\.[a-z][a-z0-9_.]{1,63}$"
        }
        require(ADAPTER_ID_PATTERN.matches(adapterId)) {
            "capability entry: adapter_id '$adapterId' must match ^[a-z][a-z0-9_]{2,63}$"
        }
        require(platform == DEFAULT_PLATFORM) {
            "capability entry: platform must be '$DEFAULT_PLATFORM'"
        }
        require(minApiLevel >= 1) { "capability entry: min_api_level must be >= 1" }
        require(maxApiLevel == null || maxApiLevel >= minApiLevel) {
            "capability entry: max_api_level must be null or >= min_api_level"
        }
        require(argumentSchemaRevision.matches(SCHEMA_REVISION_PATTERN)) {
            "capability entry: argument_schema_revision ${argumentSchemaRevision.inspect()} is invalid"
        }
        requiredPermissions.forEach { permission ->
            require(PERMISSION_PATTERN.matches(permission)) {
                "capability entry: required permission ${permission.inspect()} is not a valid " +
                    "android.permission reference"
            }
        }
        hardwareFeatures.forEach { feature ->
            require(HARDWARE_PATTERN.matches(feature)) {
                "capability entry: hardware feature ${feature.inspect()} is not a valid " +
                    "android.hardware reference"
            }
        }
        when (deviceStatus) {
            DeviceCapabilityStatus.VERIFIED -> {
                require(verification != null) {
                    "capability entry for '$toolName': VERIFIED requires test evidence"
                }
            }

            DeviceCapabilityStatus.NOT_TESTED -> {
                require(verification == null) {
                    "capability entry for '$toolName': NOT_TESTED must not carry test evidence"
                }
            }
        }
        verification?.let { evidence ->
            require(evidence.testId.isNotEmpty() && evidence.apkSha256.isNotEmpty()) {
                "capability entry for '$toolName': test evidence is all-or-nothing"
            }
            require(evidence.timestampUtc.isNotEmpty()) {
                "capability entry for '$toolName': test evidence is all-or-nothing"
            }
        }
    }

    /**
     * The contract-shaped JSON object for this entry with keys in the byte order produced by
     * the station side (`json.dumps(..., sort_keys=True)`), so `CapabilityCatalog.revision`
     * and the station control plane derive identical revision strings for identical entry sets.
     */
    fun wireObject(): JsonObject =
        buildJsonObject {
            put("adapter_id", JsonPrimitive(adapterId))
            put("api_id", JsonPrimitive(apiId))
            put("argument_schema_revision", JsonPrimitive(argumentSchemaRevision))
            put("device_status", JsonPrimitive(deviceStatus.wireName))
            put("hardware_features", wiresOf(hardwareFeatures))
            put("max_api_level", maxApiLevel?.let { JsonPrimitive(it) } ?: JsonNull)
            put("min_api_level", JsonPrimitive(minApiLevel))
            put("platform", JsonPrimitive(platform))
            put("privilege_tier", JsonPrimitive(privilegeTier.wireName))
            put("required_permissions", wiresOf(requiredPermissions))
            put("risk", JsonPrimitive(risk.wireName))
            put(
                "verification",
                buildJsonObject {
                    put("apk_sha256", evidenceWire(verification?.apkSha256))
                    put("test_id", evidenceWire(verification?.testId))
                    put("timestamp_utc", evidenceWire(verification?.timestampUtc))
                },
            )
        }

    private companion object {
        const val DEFAULT_PLATFORM = "android"
        const val DEFAULT_MIN_API_LEVEL = 33
        const val DEFAULT_ARGUMENT_SCHEMA_REVISION = "1"

        /** Tool names and adapter ids follow the station tool-id dialect. */
        val TOOL_NAME_PATTERN = Regex("^[a-z][a-z0-9_]{2,63}$")

        /** api_id follows the station operation-id dialect: android.<lowercase dotted path>. */
        val API_ID_PATTERN = Regex("^android\\.[a-z][a-z0-9_.]{1,63}$")

        val ADAPTER_ID_PATTERN = Regex("^[a-z][a-z0-9_]{2,63}$")

        val PERMISSION_PATTERN = Regex("^android\\.permission\\.[A-Z0-9_.]+$")

        val HARDWARE_PATTERN = Regex("^android\\.hardware\\.[a-z0-9_.]+$")

        val SCHEMA_REVISION_PATTERN = Regex("^[a-z0-9][a-z0-9._-]{0,31}$")

        private fun wiresOf(values: List<String>): JsonArray = JsonArray(values.map { JsonPrimitive(it) })

        private fun evidenceWire(value: String?): JsonElement = value?.let { JsonPrimitive(it) } ?: JsonNull

        private fun String.inspect(): String = "'$this'"
    }
}

/**
 * The fail-fast capability catalog for one device build.
 *
 * Entries are keyed by contract `api_id` (wire) and by un-prefixed MCP tool name (dispatch).
 * [of] rejects duplicate tool names and duplicate api ids so the catalog is a bijective
 * tool↔capability mapping. The canonical document and [revision] are computed without
 * reflection and without any serialization configuration, so the value is deterministic.
 */
class CapabilityCatalog private constructor(
    private val byApiId: Map<String, CapabilityEntry>,
    private val byToolName: Map<String, CapabilityEntry>,
) {
    /** Sha256 revision prefix over the canonical document (station-compatible format). */
    val revision: String = "sha256:" + sha256Hex(canonicalDocument())

    /** All catalog api ids in definition order. */
    val apiIds: Set<String> get() = byApiId.keys

    /** All catalog tool names (dispatch keys) in definition order. */
    val toolNames: Set<String> get() = byToolName.keys

    /**
     * The contract JSON document for the catalog: api-id keyed objects with sorted keys and a
     * compact separator style, matching the station side's canonical JSON encoding.
     */
    fun canonicalDocument(): String {
        val root =
            buildJsonObject {
                byApiId.toSortedMap().forEach { (apiId, entry) -> put(apiId, entry.wireObject()) }
            }
        return Json.encodeToString(JsonElement.serializer(), root)
    }

    /** The entry registered for [apiId], or null when the api is not catalog-listed. */
    fun forApi(apiId: String): CapabilityEntry? = byApiId[apiId]

    /** The entry registered for the un-prefixed [toolName], or null when not catalog-listed. */
    fun forTool(toolName: String): CapabilityEntry? = byToolName[toolName]

    /**
     * Startup integrity check: the registered tool set must equal the catalog tool set.
     * A missing catalog entry means a dispatched tool cannot be gated; an unregistered
     * catalog entry means the catalog overstates the device surface.
     */
    fun checkRegisteredToolNames(registered: Collection<String>): CatalogIntegrityReport {
        val registeredSet = registered.toSet()
        return CatalogIntegrityReport(
            missingCatalogEntries = registeredSet - byToolName.keys,
            unregisteredCatalogEntries = byToolName.keys - registeredSet,
        )
    }

    companion object {
        /**
         * Builds a [CapabilityCatalog], failing fast on duplicate dispatch keys or api ids.
         * Entry-level schema validation happens inside [CapabilityEntry].
         */
        fun of(entries: Collection<CapabilityEntry>): CapabilityCatalog {
            val byApiId = LinkedHashMap<String, CapabilityEntry>(entries.size)
            val byToolName = LinkedHashMap<String, CapabilityEntry>(entries.size)
            entries.forEach { entry ->
                require(byApiId.put(entry.apiId, entry) == null) {
                    "capability catalog: duplicate api_id '${entry.apiId}'"
                }
                require(byToolName.put(entry.toolName, entry) == null) {
                    "capability catalog: duplicate tool_name '${entry.toolName}'"
                }
            }
            return CapabilityCatalog(byApiId, byToolName)
        }

        /** The device catalog covering every registered MCP tool of this build. */
        fun deviceCatalog(): CapabilityCatalog = of(DEVICE_ENTRIES)

        private fun sha256Hex(value: String): String =
            MessageDigest
                .getInstance("SHA-256")
                .digest(value.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }

        /**
         * One entry per registered tool. Tiers reflect how the capability executes:
         * T1_APP = app-scope public SDK APIs; T2_TEST = automation-grade UI driving that can
         * also be reached via adb/instrumentation (accessibility actions, tree introspection,
         * text injection).
         */
        private val DEVICE_ENTRIES: List<CapabilityEntry> =
            listOf(
                // Touch actions (accessibility gesture injection).
                entry("tap", "android.ui.tap.v1", "action_executor_v1", PrivilegeTier.T2_TEST, CapabilityRisk.MUTATING),
                entry(
                    "double_tap",
                    "android.ui.double_tap.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "long_press",
                    "android.ui.long_press.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "swipe",
                    "android.ui.swipe.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "scroll",
                    "android.ui.scroll.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                // Multi-finger / path gestures (accessibility gesture API).
                entry(
                    "pinch",
                    "android.ui.pinch.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "custom_gesture",
                    "android.ui.custom_gesture.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                // Global actions (accessibility service global action dispatch).
                entry(
                    "press_back",
                    "android.ui.press_back.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "press_home",
                    "android.ui.press_home.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "press_recents",
                    "android.ui.press_recents.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "open_notifications",
                    "android.ui.open_notifications.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "open_quick_settings",
                    "android.ui.open_quick_settings.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "dismiss_keyboard",
                    "android.ui.dismiss_keyboard.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                // Node introspection and node actions.
                entry(
                    "find_nodes",
                    "android.ui.find_nodes.v1",
                    "element_finder_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.READ_ONLY,
                ),
                entry(
                    "click_node",
                    "android.ui.click_node.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "long_click_node",
                    "android.ui.long_click_node.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "tap_node",
                    "android.ui.tap_node.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "scroll_to_node",
                    "android.ui.scroll_to_node.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "get_node_details",
                    "android.ui.get_node_details.v1",
                    "element_finder_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.READ_ONLY,
                ),
                entry(
                    "wait_for_node",
                    "android.ui.wait_for_node.v1",
                    "element_finder_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.READ_ONLY,
                ),
                entry(
                    "wait_for_idle",
                    "android.ui.wait_for_idle.v1",
                    "accessibility_service_provider_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.READ_ONLY,
                ),
                // Text input (InputConnection / key event injection).
                entry(
                    "type_insert_text",
                    "android.ui.type_insert_text.v1",
                    "type_input_controller_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "type_append_text",
                    "android.ui.type_append_text.v1",
                    "type_input_controller_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "type_replace_text",
                    "android.ui.type_replace_text.v1",
                    "type_input_controller_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "type_clear_text",
                    "android.ui.type_clear_text.v1",
                    "type_input_controller_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "press_key",
                    "android.ui.press_key.v1",
                    "action_executor_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.MUTATING,
                ),
                // Screen state (screenshot + accessibility tree snapshot).
                entry(
                    "get_screen_state",
                    "android.ui.get_screen_state.v1",
                    "screen_capture_provider_v1",
                    PrivilegeTier.T2_TEST,
                    CapabilityRisk.READ_ONLY,
                ),
                // Clipboard (system ClipboardManager).
                entry(
                    "get_clipboard",
                    "android.clipboard.read.v1",
                    "clipboard_manager_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.READ_ONLY,
                ),
                entry(
                    "set_clipboard",
                    "android.clipboard.write.v1",
                    "clipboard_manager_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                // App-scoped file operations.
                entry(
                    "list_storage_locations",
                    "android.file.list_locations.v1",
                    "storage_location_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.READ_ONLY,
                ),
                entry(
                    "list_files",
                    "android.file.list.v1",
                    "file_operation_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.READ_ONLY,
                ),
                entry(
                    "read_file",
                    "android.file.read.v1",
                    "file_operation_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.READ_ONLY,
                ),
                entry(
                    "write_file",
                    "android.file.write.v1",
                    "file_operation_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "append_file",
                    "android.file.append.v1",
                    "file_operation_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "file_replace",
                    "android.file.replace.v1",
                    "file_operation_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "delete_file",
                    "android.file.delete.v1",
                    "file_operation_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                CapabilityEntry(
                    toolName = "download_from_url",
                    apiId = "android.file.download.v1",
                    adapterId = "file_operation_provider_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.NETWORK,
                    requiredPermissions = listOf("android.permission.INTERNET"),
                ),
                // App management (PackageManager / system services).
                CapabilityEntry(
                    toolName = "list_apps",
                    apiId = "android.apps.list.v1",
                    adapterId = "app_manager_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.READ_ONLY,
                    requiredPermissions = listOf("android.permission.QUERY_ALL_PACKAGES"),
                ),
                entry(
                    "open_app",
                    "android.apps.open.v1",
                    "app_manager_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                CapabilityEntry(
                    toolName = "close_app",
                    apiId = "android.apps.close.v1",
                    adapterId = "app_manager_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.MUTATING,
                    requiredPermissions = listOf("android.permission.KILL_BACKGROUND_PROCESSES"),
                ),
                // Camera capture (explicitly permission-gated at dispatch by OptionalToolPermissions).
                CapabilityEntry(
                    toolName = "list_cameras",
                    apiId = "android.camera.list.v1",
                    adapterId = "camera_provider_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.READ_ONLY,
                    requiredPermissions = listOf("android.permission.CAMERA"),
                    hardwareFeatures = listOf("android.hardware.camera"),
                ),
                CapabilityEntry(
                    toolName = "list_camera_photo_resolutions",
                    apiId = "android.camera.list_photo_resolutions.v1",
                    adapterId = "camera_provider_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.READ_ONLY,
                    requiredPermissions = listOf("android.permission.CAMERA"),
                    hardwareFeatures = listOf("android.hardware.camera"),
                ),
                CapabilityEntry(
                    toolName = "list_camera_video_resolutions",
                    apiId = "android.camera.list_video_resolutions.v1",
                    adapterId = "camera_provider_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.READ_ONLY,
                    requiredPermissions = listOf("android.permission.CAMERA"),
                    hardwareFeatures = listOf("android.hardware.camera"),
                ),
                CapabilityEntry(
                    toolName = "take_camera_photo",
                    apiId = "android.camera.take_photo.v1",
                    adapterId = "camera_provider_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.READ_ONLY,
                    requiredPermissions = listOf("android.permission.CAMERA"),
                    hardwareFeatures = listOf("android.hardware.camera"),
                ),
                CapabilityEntry(
                    toolName = "save_camera_photo",
                    apiId = "android.camera.save_photo.v1",
                    adapterId = "camera_provider_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.MUTATING,
                    requiredPermissions = listOf("android.permission.CAMERA"),
                    hardwareFeatures = listOf("android.hardware.camera"),
                ),
                CapabilityEntry(
                    toolName = "save_camera_video",
                    apiId = "android.camera.save_video.v1",
                    adapterId = "camera_provider_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.MUTATING,
                    requiredPermissions = listOf("android.permission.CAMERA", "android.permission.RECORD_AUDIO"),
                    hardwareFeatures = listOf("android.hardware.camera"),
                ),
                // Intent dispatch.
                entry(
                    "send_intent",
                    "android.intent.send.v1",
                    "intent_dispatcher_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "open_uri",
                    "android.intent.open_uri.v1",
                    "intent_dispatcher_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                // Notifications (gated by the notification-listener binding, not a runtime permission).
                entry(
                    "notification_list",
                    "android.notifications.list.v1",
                    "notification_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.READ_ONLY,
                ),
                entry(
                    "notification_open",
                    "android.notifications.open.v1",
                    "notification_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "notification_dismiss",
                    "android.notifications.dismiss.v1",
                    "notification_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "notification_snooze",
                    "android.notifications.snooze.v1",
                    "notification_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "notification_action",
                    "android.notifications.action.v1",
                    "notification_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                entry(
                    "notification_reply",
                    "android.notifications.reply.v1",
                    "notification_provider_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.MUTATING,
                ),
                // Location (explicitly permission-gated at dispatch by OptionalToolPermissions).
                CapabilityEntry(
                    toolName = "get_location",
                    apiId = "android.location.get.v1",
                    adapterId = "location_provider_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.READ_ONLY,
                    requiredPermissions =
                        listOf(
                            "android.permission.ACCESS_FINE_LOCATION",
                            "android.permission.ACCESS_COARSE_LOCATION",
                        ),
                    hardwareFeatures = listOf("android.hardware.location.gps"),
                ),
                // Sharing (device-to-caller content transfer and link creation).
                entry(
                    "get_shared_content",
                    "android.sharing.get_shared_content.v1",
                    "shared_content_inbox_v1",
                    PrivilegeTier.T1_APP,
                    CapabilityRisk.READ_ONLY,
                ),
                CapabilityEntry(
                    toolName = "share_file_via_web",
                    apiId = "android.sharing.create_link.v1",
                    adapterId = "ephemeral_file_link_service_v1",
                    privilegeTier = PrivilegeTier.T1_APP,
                    risk = CapabilityRisk.NETWORK,
                    requiredPermissions = listOf("android.permission.INTERNET"),
                ),
            )

        private fun entry(
            toolName: String,
            apiId: String,
            adapterId: String,
            privilegeTier: PrivilegeTier,
            risk: CapabilityRisk,
        ): CapabilityEntry = CapabilityEntry(toolName, apiId, adapterId, privilegeTier, risk)
    }
}

/** Difference between the registered tool set and the catalog tool set (startup integrity). */
data class CatalogIntegrityReport(
    val missingCatalogEntries: Set<String>,
    val unregisteredCatalogEntries: Set<String>,
) {
    /** True when every dispatched tool is catalog-listed and the catalog lists nothing extra. */
    val intact: Boolean
        get() = missingCatalogEntries.isEmpty() && unregisteredCatalogEntries.isEmpty()
}
