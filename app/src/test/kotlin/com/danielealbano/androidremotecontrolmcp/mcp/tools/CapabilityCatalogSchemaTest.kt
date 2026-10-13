package com.danielealbano.androidremotecontrolmcp.mcp.tools

import com.danielealbano.androidremotecontrolmcp.data.model.OptionalToolPermission
import com.danielealbano.androidremotecontrolmcp.data.model.OptionalToolPermissions
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@DisplayName("CapabilityCatalog schema, integrity and revision")
class CapabilityCatalogSchemaTest {
    private fun validEntry(
        toolName: String = "tap",
        apiId: String = "android.ui.tap.v1",
        adapterId: String = "action_executor_v1",
    ): CapabilityEntry =
        CapabilityEntry(
            toolName = toolName,
            apiId = apiId,
            adapterId = adapterId,
            privilegeTier = PrivilegeTier.T2_TEST,
            risk = CapabilityRisk.MUTATING,
        )

    @Test
    fun `valid entry passes schema validation`() {
        val entry =
            CapabilityEntry(
                toolName = "download_from_url",
                apiId = "android.file.download.v1",
                adapterId = "file_operation_provider_v1",
                privilegeTier = PrivilegeTier.T1_APP,
                risk = CapabilityRisk.NETWORK,
                requiredPermissions = listOf("android.permission.INTERNET"),
                hardwareFeatures = listOf("android.hardware.location.gps"),
            )

        assertEquals("android.file.download.v1", entry.apiId)
        assertEquals(33, entry.minApiLevel)
        assertNull(entry.maxApiLevel)
    }

    @Test
    fun `entry rejects malformed identifiers`() {
        assertThrows<IllegalArgumentException> { validEntry(toolName = "Tap") }
        assertThrows<IllegalArgumentException> { validEntry(toolName = "a") }
        assertThrows<IllegalArgumentException> { validEntry(apiId = "ui.tap.v1") }
        assertThrows<IllegalArgumentException> { validEntry(apiId = "android.Ui.Tap.v1") }
        assertThrows<IllegalArgumentException> { validEntry(adapterId = "Action_Executor") }
    }

    @Test
    fun `entry rejects platform, api level and schema revision violations`() {
        assertThrows<IllegalArgumentException> {
            validEntry().copy(platform = "linux")
        }
        assertThrows<IllegalArgumentException> {
            validEntry().copy(minApiLevel = 0)
        }
        assertThrows<IllegalArgumentException> {
            validEntry().copy(minApiLevel = 34, maxApiLevel = 33)
        }
        assertThrows<IllegalArgumentException> {
            validEntry().copy(argumentSchemaRevision = "UPPER")
        }
        assertThrows<IllegalArgumentException> {
            validEntry().copy(argumentSchemaRevision = "")
        }
    }

    @Test
    fun `entry rejects non-contract permission and hardware references`() {
        assertThrows<IllegalArgumentException> {
            validEntry().copy(requiredPermissions = listOf("android.permission.camera"))
        }
        assertThrows<IllegalArgumentException> {
            validEntry().copy(requiredPermissions = listOf("CAMERA"))
        }
        assertThrows<IllegalArgumentException> {
            validEntry().copy(hardwareFeatures = listOf("android.hardware.Camera"))
        }
        assertThrows<IllegalArgumentException> {
            validEntry().copy(hardwareFeatures = listOf("android.sensor.camera"))
        }
    }

    @Test
    fun `verification evidence is all-or-nothing`() {
        val evidence = CapabilityVerification("CapabilityCatalogSchemaTest", "sha256:abc", "2026-02-15T00:00:00Z")
        val verified = validEntry().copy(deviceStatus = DeviceCapabilityStatus.VERIFIED, verification = evidence)
        assertEquals(DeviceCapabilityStatus.VERIFIED, verified.deviceStatus)

        assertThrows<IllegalArgumentException> {
            validEntry().copy(deviceStatus = DeviceCapabilityStatus.VERIFIED)
        }
        assertThrows<IllegalArgumentException> {
            validEntry().copy(
                deviceStatus = DeviceCapabilityStatus.VERIFIED,
                verification = CapabilityVerification("", "sha256:abc", "2026-02-15T00:00:00Z"),
            )
        }
        assertThrows<IllegalArgumentException> {
            validEntry().copy(verification = evidence)
        }
    }

    @Test
    fun `privilege tier and risk wire names round-trip`() {
        PrivilegeTier.entries.forEach { tier -> assertEquals(tier, PrivilegeTier.fromWireName(tier.wireName)) }
        assertNull(PrivilegeTier.fromWireName("T6_FUTURE"))
        assertNull(PrivilegeTier.fromWireName("t1_app"))
        CapabilityRisk.entries.forEach { risk -> CapabilityRisk.fromWireName(risk.wireName) }
        assertNull(CapabilityRisk.fromWireName("unknown"))
        DeviceCapabilityStatus.entries.forEach { status ->
            assertEquals(status, DeviceCapabilityStatus.fromWireName(status.wireName))
        }
        assertNull(DeviceCapabilityStatus.fromWireName("unverified"))
    }

    @Test
    fun `catalog rejects duplicate tool names and api ids`() {
        val clash =
            CapabilityEntry(
                toolName = "tap_alias",
                apiId = "android.ui.tap.v1",
                adapterId = "action_executor_v1",
                privilegeTier = PrivilegeTier.T2_TEST,
                risk = CapabilityRisk.MUTATING,
            )
        assertThrows<IllegalArgumentException> { CapabilityCatalog.of(listOf(validEntry(), clash)) }

        val secondTool =
            CapabilityEntry(
                toolName = "tap2",
                apiId = "android.ui.tap2.v1",
                adapterId = "action_executor_v1",
                privilegeTier = PrivilegeTier.T2_TEST,
                risk = CapabilityRisk.MUTATING,
            )
        assertThrows<IllegalArgumentException> {
            CapabilityCatalog.of(listOf(validEntry(), secondTool.copy(apiId = "android.ui.tap.v1")))
        }
    }

    @Test
    fun `device catalog covers exactly the registered tool surface`() {
        val catalog = CapabilityCatalog.deviceCatalog()
        assertEquals(DEVICE_ENTRY_TOOL_NAMES, catalog.toolNames)
        assertEquals(DEVICE_ENTRY_TOOL_NAMES.size, catalog.apiIds.size)
    }

    @Test
    fun `device catalog cross-checks the optional permission gating surface`() {
        val catalog = CapabilityCatalog.deviceCatalog()
        val permissionKeyedTools =
            OptionalToolPermissions.TOOLS_BY_PERMISSION.values
                .flatten()
                .toSet()
        permissionKeyedTools.forEach { toolName -> assertTrue(catalog.toolNames.contains(toolName)) }

        OptionalToolPermissions.TOOLS_BY_PERMISSION[OptionalToolPermission.CAMERA]!!.forEach { toolName ->
            val entry = catalog.forTool(toolName)!!
            assertTrue(entry.requiredPermissions.contains("android.permission.CAMERA"))
        }
        val locationEntry = catalog.forTool("get_location")!!
        assertTrue(locationEntry.requiredPermissions.contains("android.permission.ACCESS_FINE_LOCATION"))
    }

    @Test
    fun `revision is deterministic sha256 format`() {
        val first = CapabilityCatalog.deviceCatalog().revision
        val second = CapabilityCatalog.deviceCatalog().revision
        assertEquals(first, second)
        assertTrue(first.startsWith("sha256:"))
        assertEquals("sha256:".length + 64, first.length)
        assertTrue(first.drop("sha256:".length).all { it.isDigit() || it in 'a'..'f' })
    }

    @Test
    fun `canonical document uses contract keys in sorted order`() {
        val catalog = CapabilityCatalog.deviceCatalog()
        val root = Json.parseToJsonElement(catalog.canonicalDocument()).jsonObject
        assertTrue(root.containsKey("android.ui.tap.v1"))
        val entryJson = root["android.ui.tap.v1"]!!.jsonObject
        assertEquals(
            listOf(
                "adapter_id",
                "api_id",
                "argument_schema_revision",
                "device_status",
                "hardware_features",
                "max_api_level",
                "min_api_level",
                "platform",
                "privilege_tier",
                "required_permissions",
                "risk",
                "verification",
            ),
            entryJson.keys.toList(),
        )
        assertEquals("T2_TEST", entryJson["privilege_tier"]!!.jsonPrimitive.content)
        val document = catalog.canonicalDocument()
        assertTrue(document.contains("\"android.ui.tap.v1\":{\"adapter_id\""))
    }

    @Test
    fun `integrity report catalogs registration drift both ways`() {
        val catalog = CapabilityCatalog.of(listOf(validEntry()))
        val intact = catalog.checkRegisteredToolNames(listOf("tap"))
        assertTrue(intact.intact)

        val missing = catalog.checkRegisteredToolNames(listOf("tap", "unknown_tool"))
        assertEquals(setOf("unknown_tool"), missing.missingCatalogEntries)
        assertTrue(missing.unregisteredCatalogEntries.isEmpty())

        val unregistered = catalog.checkRegisteredToolNames(emptyList())
        assertTrue(unregistered.missingCatalogEntries.isEmpty())
        assertEquals(setOf("tap"), unregistered.unregisteredCatalogEntries)
    }

    @Test
    fun `gated-off surfaces report drift that is not fatal`() {
        // The gate that consumes this lives in McpServerService.registerAllTools, which needs
        // Hilt/Context and is jacoco-excluded, so it cannot be exercised here. What is pinned is
        // the data invariant the gate relies on: the two ways LAB_HARDENED shrinks the registered
        // surface (download_from_url gated off in FileTools, a denylist-shaped config denying
        // every tool) produce unregistered catalog entries only, never missing ones. Only a
        // registered tool without a catalog entry is fatal.
        val catalog = CapabilityCatalog.deviceCatalog()

        val gatedOff = catalog.checkRegisteredToolNames(DEVICE_ENTRY_TOOL_NAMES - "download_from_url")
        assertFalse(gatedOff.intact, "drift is still recorded")
        assertTrue(gatedOff.missingCatalogEntries.isEmpty(), "a gated-off catalog entry is not fatal")
        assertEquals(setOf("download_from_url"), gatedOff.unregisteredCatalogEntries)

        val deniedAll = catalog.checkRegisteredToolNames(emptyList())
        assertTrue(deniedAll.missingCatalogEntries.isEmpty(), "an empty hardened surface is not fatal")
    }

    private companion object {
        /** Every tool the device registers must have exactly one catalog entry. */
        val DEVICE_ENTRY_TOOL_NAMES: Set<String> =
            setOf(
                // Touch + gesture actions.
                "tap",
                "double_tap",
                "long_press",
                "swipe",
                "scroll",
                "pinch",
                "custom_gesture",
                // Global system actions.
                "press_back",
                "press_home",
                "press_recents",
                "open_notifications",
                "open_quick_settings",
                "dismiss_keyboard",
                // Node actions and introspection.
                "find_nodes",
                "click_node",
                "long_click_node",
                "tap_node",
                "scroll_to_node",
                "get_node_details",
                "wait_for_node",
                "wait_for_idle",
                // Text input.
                "type_insert_text",
                "type_append_text",
                "type_replace_text",
                "type_clear_text",
                "press_key",
                // Screen state.
                "get_screen_state",
                // Clipboard.
                "get_clipboard",
                "set_clipboard",
                // Files.
                "list_storage_locations",
                "list_files",
                "read_file",
                "write_file",
                "append_file",
                "file_replace",
                "delete_file",
                "download_from_url",
                // Apps.
                "list_apps",
                "open_app",
                "close_app",
                // Camera.
                "list_cameras",
                "list_camera_photo_resolutions",
                "list_camera_video_resolutions",
                "take_camera_photo",
                "save_camera_photo",
                "save_camera_video",
                // Intents.
                "send_intent",
                "open_uri",
                // Notifications.
                "notification_list",
                "notification_open",
                "notification_dismiss",
                "notification_snooze",
                "notification_action",
                "notification_reply",
                // Location.
                "get_location",
                // Sharing.
                "get_shared_content",
                "share_file_via_web",
            )
    }
}
