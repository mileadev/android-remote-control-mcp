package com.danielealbano.androidremotecontrolmcp.manifest

import com.danielealbano.androidremotecontrolmcp.BuildConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Guards the labHardened build surface (handoff backlog item H-07: manifest/exported
 * surfaces + build variants).
 *
 * The lab image runs on disposable, shared devices, so its manifest surface is reduced to
 * the job-required minimum. These tests parse the checked-in overlays — the same source
 * documents the manifest merger consumes — so a reverted or misconfigured overlay fails the
 * build instead of quietly shipping a broader surface. Merged-output parity is verified by
 * the `process*Manifest` Gradle tasks during validation.
 *
 * Merge mechanics under test:
 * - `src/labHardened` (flavor source set) outranks `src/main`, so `tools:node="remove"`
 *   strips upstream permissions/components for lab flavors only.
 * - `src/labHardenedDebug` (flavor x buildType combined source set) outranks the debug
 *   build-type source set, so it is the only place where the debug-declared test receivers
 *   can be stripped from labHardenedDebug, which merges src/debug.
 */
@DisplayName("Build surface (labHardened)")
class BuildSurfaceTest {
    @Test
    fun `labHardened overlay removes the debug-only test receivers`() {
        val document = parseManifest(LAB_HARDENED_DEBUG_OVERLAY)

        DEBUG_ONLY_RECEIVERS.forEach { name ->
            document.requireRemoval(RECEIVER_TAG, name)
        }
    }

    @Test
    fun `labHardened overlay removes boot auto-start from the lab image`() {
        val document = parseManifest(LAB_HARDENED_OVERLAY)

        document.requireRemoval(RECEIVER_TAG, BOOT_RECEIVER)
        document.requireRemoval(PERMISSION_TAG, RECEIVE_BOOT_COMPLETED)
    }

    @Test
    fun `labHardened overlay minimizes permissions outside the lab job`() {
        val document = parseManifest(LAB_HARDENED_OVERLAY)

        REMOVED_IN_LAB_HARDENED.forEach { name ->
            document.requireRemoval(PERMISSION_TAG, name)
        }
    }

    @Test
    fun `labHardened overlay keeps permissions the controller job requires`() {
        val main = parseManifest(MAIN_MANIFEST)
        val overlay = parseManifest(LAB_HARDENED_OVERLAY)

        REQUIRED_FOR_LAB_JOB.forEach { name ->
            assertTrue(main.elements(PERMISSION_TAG).any { it.getAttribute("android:name") == name }) {
                "$name is no longer declared in $MAIN_MANIFEST — update BuildSurfaceTest."
            }
            assertTrue(
                overlay
                    .elements(PERMISSION_TAG)
                    .none { it.getAttribute("android:name") == name && it.getAttribute("tools:node") == "remove" },
            ) {
                "labHardened must not remove $name: EventChannelService starts a location-type " +
                    "foreground service (Android 14 enforces the permission at startForeground() " +
                    "time) and the McpServerService/notification/terminate-app surface depends on " +
                    "these permissions."
            }
        }
    }

    @Test
    fun `labHardened overlay keeps a launchable-app visibility fallback`() {
        val document = parseManifest(LAB_HARDENED_OVERLAY)
        val queries = document.elements(QUERIES_TAG)

        assertTrue(queries.isNotEmpty()) {
            "The <queries> launcher-intent block is required after QUERY_ALL_PACKAGES removal, " +
                "otherwise the app-manager tools cannot resolve launchable apps on the lab image."
        }
        val intent =
            queries
                .flatMap { it.elements(INTENT_TAG) }
                .firstOrNull() ?: error("<queries> must declare an <intent> block")
        val action = intent.elements(ACTION_TAG).firstOrNull() ?: error("<intent> must declare an <action>")
        val category =
            intent
                .elements(CATEGORY_TAG)
                .firstOrNull() ?: error("<intent> must declare a <category>")

        assertEquals(
            MAIN_ACTION,
            action.getAttribute("android:name"),
        )
        assertEquals(
            LAUNCHER_CATEGORY,
            category.getAttribute("android:name"),
        )
    }

    @Test
    fun `main manifest keeps the boot surface for the upstream flavors`() {
        val main = parseManifest(MAIN_MANIFEST)

        assertTrue(main.elements(RECEIVER_TAG).any { isBootReceiverName(it.componentName()) }) {
            "The boot receiver removal must stay confined to the labHardened overlay; the upstream " +
                "gms/foss flavors keep auto-start behavior."
        }
    }

    @Test
    fun `labHardened unit tests run against the hardened build configuration`() {
        assertTrue(BuildConfig.LAB_HARDENED) {
            "BuildSurfaceTest must run under a labHardened unit-test variant where " +
                "BuildConfig.LAB_HARDENED is true; if this fails, the test source set is being " +
                "compiled against a non-hardened variant."
        }
    }

    private fun Element.elements(tag: String): List<Element> {
        val nodes = getElementsByTagName(tag)
        return (0 until nodes.length).map { index -> nodes.item(index) as Element }
    }

    private fun Element.componentName(): String = getAttribute("android:name")

    // The main manifest declares components with package-relative names; overlay removals use
    // fully-qualified names, and the manifest merger resolves both against the namespace.
    private fun isBootReceiverName(name: String): Boolean = name == BOOT_RECEIVER || name == BOOT_RECEIVER_RELATIVE

    private fun Element.requireRemoval(
        tag: String,
        name: String,
    ): Element =
        elements(tag)
            .firstOrNull { it.componentName() == name && it.getAttribute("tools:node") == "remove" }
            ?: error("$tag '$name' is not marked tools:node=\"remove\" in a labHardened overlay")

    private fun parseManifest(relativePath: String): Element {
        val file =
            listOf(File(relativePath), File("app", relativePath)).firstOrNull { it.isFile }
                ?: error("Manifest not found: $relativePath (cwd=${File(".").absolutePath})")

        return DocumentBuilderFactory
            .newInstance()
            .apply { setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) }
            .newDocumentBuilder()
            .parse(file)
            .documentElement
    }

    private companion object {
        const val MAIN_MANIFEST = "src/main/AndroidManifest.xml"
        const val LAB_HARDENED_OVERLAY = "src/labHardened/AndroidManifest.xml"
        const val LAB_HARDENED_DEBUG_OVERLAY = "src/labHardenedDebug/AndroidManifest.xml"
        const val RECEIVER_TAG = "receiver"
        const val PERMISSION_TAG = "uses-permission"
        const val QUERIES_TAG = "queries"
        const val INTENT_TAG = "intent"
        const val ACTION_TAG = "action"
        const val CATEGORY_TAG = "category"

        const val BOOT_RECEIVER =
            "com.danielealbano.androidremotecontrolmcp.services.mcp.BootCompletedReceiver"
        const val BOOT_RECEIVER_RELATIVE = ".services.mcp.BootCompletedReceiver"
        const val RECEIVE_BOOT_COMPLETED = "android.permission.RECEIVE_BOOT_COMPLETED"
        const val MAIN_ACTION = "android.intent.action.MAIN"
        const val LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"

        val DEBUG_ONLY_RECEIVERS =
            listOf(
                "com.danielealbano.androidremotecontrolmcp.debug.E2EConfigReceiver",
                "com.danielealbano.androidremotecontrolmcp.debug.OAuthApprovalTestReceiver",
            )

        val REMOVED_IN_LAB_HARDENED =
            listOf(
                RECEIVE_BOOT_COMPLETED,
                "android.permission.QUERY_ALL_PACKAGES",
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_MEDIA_IMAGES",
                "android.permission.READ_MEDIA_VIDEO",
                "android.permission.READ_MEDIA_AUDIO",
                "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
            )

        val REQUIRED_FOR_LAB_JOB =
            listOf(
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.FOREGROUND_SERVICE",
                "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
                "android.permission.POST_NOTIFICATIONS",
                "android.permission.KILL_BACKGROUND_PROCESSES",
                "android.permission.ACCESS_WIFI_STATE",
                "android.permission.CHANGE_WIFI_STATE",
                "android.permission.NEARBY_WIFI_DEVICES",
                "android.permission.FOREGROUND_SERVICE_LOCATION",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
            )
    }
}
