package com.danielealbano.androidremotecontrolmcp.integration

import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.data.crypto.PlaintextSecretCipher
import com.danielealbano.androidremotecontrolmcp.data.model.ServerLogEntry
import com.danielealbano.androidremotecontrolmcp.data.model.ToolPermissionsConfig
import com.danielealbano.androidremotecontrolmcp.data.repository.EventChannelSettingsImpl
import com.danielealbano.androidremotecontrolmcp.data.repository.SettingsChangeLogger
import com.danielealbano.androidremotecontrolmcp.data.repository.SettingsRepositoryImpl
import com.danielealbano.androidremotecontrolmcp.mcp.tools.ToolPolicyGate
import com.danielealbano.androidremotecontrolmcp.services.accessibility.AccessibilityNodeData
import com.danielealbano.androidremotecontrolmcp.services.accessibility.BoundsData
import com.danielealbano.androidremotecontrolmcp.services.accessibility.ScreenInfo
import com.danielealbano.androidremotecontrolmcp.testutil.RecordingServerLogRepository
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockkStatic
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Integration tests for the fail-closed tool capability policy (handoff item H-03,
 * acceptance V05/V11/V18). Dispatch-time enforcement is exercised with the gate wired
 * exactly like the hardened production path: the gate reads the live policy from the
 * repository on every tool call and fails closed on store read errors.
 *
 * On gms/foss flavors the same documents flow through the permissive upstream parsing,
 * so tests branch on [BuildConfig.LAB_HARDENED] and prove both behaviors stay isolated.
 *
 * Registration uses the default permissive [ToolPermissionsConfig] unless a test
 * exercises the registration-time snapshot, so denial here can only come from the
 * dispatch gate (defense in depth: blocked at dispatch, not merely hidden from
 * discovery).
 */
@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("ToolPolicyLabTest")
class ToolPolicyLabTest {
    private val sampleTree =
        AccessibilityNodeData(
            id = "node_root",
            className = "android.widget.FrameLayout",
            bounds = BoundsData(0, 0, 1080, 2400),
            visible = true,
            enabled = true,
            children =
                listOf(
                    AccessibilityNodeData(
                        id = "node_btn",
                        className = "android.widget.Button",
                        text = "OK",
                        bounds = BoundsData(100, 200, 300, 260),
                        clickable = true,
                        visible = true,
                        enabled = true,
                    ),
                ),
        )

    private val sampleScreenInfo =
        ScreenInfo(
            width = 1080,
            height = 2400,
            densityDpi = 420,
            orientation = "portrait",
        )

    @TempDir
    lateinit var tempDir: File

    private val testDispatcher = UnconfinedTestDispatcher()
    private val testScope = TestScope(testDispatcher)

    private lateinit var dataStore: DataStore<Preferences>
    private lateinit var repository: SettingsRepositoryImpl
    private lateinit var deps: MockDependencies

    private var testFileCounter = 0

    @BeforeEach
    fun setUp() {
        McpIntegrationTestHelper.mockAndroidLog()
        // SettingsRepositoryImpl can log warnings with a message AND throwable.
        mockkStatic(Log::class)
        every { Log.w(any(), any(), any()) } returns 0

        testFileCounter++
        dataStore =
            PreferenceDataStoreFactory.create(
                scope = testScope.backgroundScope,
                produceFile = { File(tempDir, "tool_policy_lab_$testFileCounter.preferences_pb") },
            )
        val changeLogger =
            SettingsChangeLogger(
                RecordingServerLogRepository(),
                testDispatcher,
                SettingsChangeLogger.COALESCE_WINDOW_MS,
            )
        repository =
            SettingsRepositoryImpl(
                dataStore,
                changeLogger,
                EventChannelSettingsImpl(dataStore, changeLogger),
                PlaintextSecretCipher,
            )
        deps = McpIntegrationTestHelper.createMockDependencies()
        coEvery { deps.actionExecutor.tap(500f, 800f) } returns Result.success(Unit)
        coEvery { deps.appManager.openApp(any()) } returns Result.success(Unit)
    }

    @AfterEach
    fun tearDown() {
        McpIntegrationTestHelper.unmockAndroidLog()
    }

    /** Gate wired like the hardened production dispatch path: live per-call policy read. */
    private fun toolPolicyGate(): ToolPolicyGate = ToolPolicyGate { repository.getServerConfig().toolPermissionsConfig }

    private suspend fun storePolicyJson(json: String) {
        dataStore.edit { prefs -> prefs[stringPreferencesKey("tool_permissions")] = json }
    }

    @Test
    fun deniesMalformedEmptyUnknownVersionOrMissingPolicy() =
        testScope.runTest {
            McpIntegrationTestHelper.withTestApplication(deps, toolPolicyGate = toolPolicyGate()) { client, deps ->
                var allowedCalls = 0
                val badPolicies =
                    listOf(
                        "{ corrupted",
                        "{}",
                        """{"schemaVersion":2,"allowedToolIds":["tap"],"disabledParams":{}}""",
                        """{"schemaVersion":1,"allowedToolIds":["tap"]}""",
                    )
                for (policy in badPolicies) {
                    storePolicyJson(policy)
                    val result = client.callTool(name = "android_tap", arguments = mapOf("x" to 500, "y" to 800))
                    if (BuildConfig.LAB_HARDENED) {
                        assertTrue(result.isError == true)
                        val text = (result.content[0] as TextContent).text
                        assertTrue(text.contains("denied by the tool capability policy"))
                        assertFalse(text.contains("corrupted"))
                    } else {
                        assertNotEquals(true, result.isError)
                        allowedCalls++
                    }
                }
                // Missing document (key absent entirely) behaves like a corrupt revision.
                dataStore.edit { prefs -> prefs.remove(stringPreferencesKey("tool_permissions")) }
                val missing = client.callTool(name = "android_tap", arguments = mapOf("x" to 500, "y" to 800))
                if (BuildConfig.LAB_HARDENED) {
                    assertTrue(missing.isError == true)
                } else {
                    assertNotEquals(true, missing.isError)
                    allowedCalls++
                }
                coVerify(exactly = if (BuildConfig.LAB_HARDENED) 0 else allowedCalls) {
                    deps.actionExecutor.tap(any(), any())
                }
            }
        }

    @Test
    fun deniesUnknownToolsAndParameters() =
        testScope.runTest {
            val policy =
                """{"schemaVersion":1,"allowedToolIds":["tap","get_screen_state"],""" +
                    """"disabledParams":{"get_screen_state":["include_screenshot"]},"disabledTools":[]}"""
            storePolicyJson(policy)

            // Registration snapshot exercises the registration-time (deny-by-default
            // allowlist) filter: only allowlisted tools are exposed.
            val registrationPerms =
                ToolPermissionsConfig(
                    disabledParams = mapOf("get_screen_state" to setOf("include_screenshot")),
                    allowedToolIds = setOf("tap", "get_screen_state"),
                )
            McpIntegrationTestHelper.setupMultiWindowMock(deps, sampleTree, sampleScreenInfo)
            McpIntegrationTestHelper.withTestApplication(
                deps,
                perms = registrationPerms,
                toolPolicyGate = toolPolicyGate(),
            ) { client, _ ->
                assertRegistrationSnapshotFiltersUnknownTools(client)
            }

            // Dispatch gate: with a permissive registration snapshot every tool is
            // registered (discovery shows it), yet only allowlisted tools execute.
            McpIntegrationTestHelper.withTestApplication(deps, toolPolicyGate = toolPolicyGate()) { client, deps ->
                assertDispatchGateDeniesUnknownTool(client, deps)
            }
        }

    private suspend fun assertRegistrationSnapshotFiltersUnknownTools(client: Client) {
        val names =
            client
                .listTools()
                .tools
                .map { it.name }
                .toSet()
        assertTrue(names.contains("android_tap"))
        assertTrue(names.contains("android_get_screen_state"))
        assertFalse(names.contains("android_open_app"))

        val tap = client.callTool(name = "android_tap", arguments = mapOf("x" to 500, "y" to 800))
        assertNotEquals(true, tap.isError)
        coVerify(exactly = 1) { deps.actionExecutor.tap(any(), any()) }

        // Tool allowed, denied parameter stripped: text-only result, no capture.
        val state =
            client.callTool(
                name = "android_get_screen_state",
                arguments = mapOf("include_screenshot" to true),
            )
        assertNotEquals(true, state.isError)
        assertEquals(1, state.content.size)
        assertTrue(state.content[0] is TextContent)
        coVerify(exactly = 0) {
            deps.screenCaptureProvider.captureScreenshotBitmap(any(), any())
        }
    }

    private suspend fun assertDispatchGateDeniesUnknownTool(
        client: Client,
        deps: MockDependencies,
    ) {
        val names =
            client
                .listTools()
                .tools
                .map { it.name }
                .toSet()
        assertTrue(names.contains("android_open_app"))

        val denied =
            client.callTool(name = "android_open_app", arguments = mapOf("package_id" to "com.test.app"))
        if (BuildConfig.LAB_HARDENED) {
            assertTrue(denied.isError == true)
            assertTrue(
                (denied.content[0] as TextContent).text.contains("denied by the tool capability policy"),
            )
        } else {
            assertNotEquals(true, denied.isError)
        }
        coVerify(exactly = if (BuildConfig.LAB_HARDENED) 0 else 1) { deps.appManager.openApp(any()) }
    }

    @Test
    fun checksPolicyAfterRestartAndAtomicUpdate() =
        testScope.runTest {
            val policy =
                """{"schemaVersion":1,"allowedToolIds":["tap"],"disabledParams":{},"disabledTools":[]}"""
            storePolicyJson(policy)

            McpIntegrationTestHelper.withTestApplication(deps, toolPolicyGate = toolPolicyGate()) { client, deps ->
                // An explicitly allowlisted tool works.
                val allowed =
                    client.callTool(name = "android_tap", arguments = mapOf("x" to 500, "y" to 800))
                assertNotEquals(true, allowed.isError)
                coVerify(exactly = 1) { deps.actionExecutor.tap(any(), any()) }

                // Atomic mid-run policy update: the same session denies the tool right
                // after the repository write (no restart needed).
                repository.updateToolEnabled("tap", false)
                val denied =
                    client.callTool(name = "android_tap", arguments = mapOf("x" to 500, "y" to 800))
                assertTrue(denied.isError == true)
                coVerify(exactly = 1) { deps.actionExecutor.tap(any(), any()) }

                val callLogs = deps.serverLog.ofType(ServerLogEntry.Type.TOOL_CALL)
                assertEquals("denied", callLogs.last().message)
            }

            // Restart: a fresh session re-derives the deny purely from the persisted store.
            McpIntegrationTestHelper.withTestApplication(deps, toolPolicyGate = toolPolicyGate()) { client, deps ->
                val denied =
                    client.callTool(name = "android_tap", arguments = mapOf("x" to 500, "y" to 800))
                assertTrue(denied.isError == true)
                coVerify(exactly = 1) { deps.actionExecutor.tap(any(), any()) } // handler ran only before the update
            }
        }
}
