package com.danielealbano.androidremotecontrolmcp.data.repository

import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.data.crypto.PlaintextSecretCipher
import com.danielealbano.androidremotecontrolmcp.data.model.ToolPermissionsConfig
import com.danielealbano.androidremotecontrolmcp.testutil.RecordingServerLogRepository
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Repository-level tests for the fail-closed tool capability policy. Tests that branch on
 * [BuildConfig.LAB_HARDENED] assert the hardened deny-by-default behavior on the
 * labHardened flavor while proving gms/foss keep the upstream permissive fallback.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("SettingsRepositoryImpl tool policy")
class SettingsRepositoryImplPolicyTest {
    @TempDir
    lateinit var tempDir: File

    private val testDispatcher = UnconfinedTestDispatcher()
    private val testScope = TestScope(testDispatcher)

    private lateinit var dataStore: DataStore<Preferences>
    private lateinit var repository: SettingsRepositoryImpl

    private var testFileCounter = 0

    @BeforeEach
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.w(any<String>(), any<String>()) } returns 0
        every { Log.w(any<String>(), any<String>(), any()) } returns 0
        every { Log.e(any(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0

        testFileCounter++
        dataStore =
            PreferenceDataStoreFactory.create(
                scope = testScope.backgroundScope,
                produceFile = { File(tempDir, "tool_policy_settings_$testFileCounter.preferences_pb") },
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
    }

    @AfterEach
    fun tearDown() {
        unmockkStatic(Log::class)
    }

    private suspend fun storePolicyJson(json: String) {
        dataStore.edit { prefs -> prefs[stringPreferencesKey("tool_permissions")] = json }
    }

    private suspend fun storedPolicyJson(): String? = dataStore.data.first()[stringPreferencesKey("tool_permissions")]

    @Test
    fun `missing stored document resolves by policy mode`() =
        testScope.runTest {
            val config = repository.getServerConfig().toolPermissionsConfig
            if (BuildConfig.LAB_HARDENED) {
                assertEquals(ToolPermissionsConfig.DENY_ALL, config)
                assertFalse(config.isToolEnabled("tap"))
            } else {
                assertEquals(ToolPermissionsConfig(), config)
                assertTrue(config.isToolEnabled("tap"))
            }
        }

    @Test
    fun `corrupt stored document resolves by policy mode`() =
        testScope.runTest {
            storePolicyJson("{ corrupted")
            val config = repository.getServerConfig().toolPermissionsConfig
            if (BuildConfig.LAB_HARDENED) {
                assertEquals(ToolPermissionsConfig.DENY_ALL, config)
                assertFalse(config.isToolEnabled("tap"))
            } else {
                assertEquals(ToolPermissionsConfig(), config)
                assertTrue(config.isToolEnabled("tap"))
            }
        }

    @Test
    fun `upstream format stored document resolves by policy mode`() =
        testScope.runTest {
            storePolicyJson("""{"disabledTools":["tap"],"disabledParams":{}}""")
            val config = repository.getServerConfig().toolPermissionsConfig
            if (BuildConfig.LAB_HARDENED) {
                // Pre-policy documents are never trusted as policy revisions.
                assertEquals(ToolPermissionsConfig.DENY_ALL, config)
            } else {
                assertEquals(ToolPermissionsConfig(disabledTools = setOf("tap")), config)
                assertTrue(config.isToolEnabled("swipe"))
            }
        }

    @Test
    fun `updateToolPermissionsConfig persists a versioned policy document on hardened build`() =
        testScope.runTest {
            val policy =
                ToolPermissionsConfig(
                    disabledTools = setOf("swipe"),
                    disabledParams = mapOf("tap" to setOf("x")),
                    allowedToolIds = setOf("tap"),
                )
            repository.updateToolPermissionsConfig(policy)

            val config = repository.getServerConfig().toolPermissionsConfig
            if (BuildConfig.LAB_HARDENED) {
                assertEquals(policy, config)
                assertEquals(
                    """{"schemaVersion":1,"allowedToolIds":["tap"],"disabledParams":{"tap":["x"]},""" +
                        """"disabledTools":["swipe"]}""",
                    storedPolicyJson(),
                )
            } else {
                // Upstream parsing only models the denylist keys.
                assertEquals(
                    ToolPermissionsConfig(disabledTools = setOf("swipe"), disabledParams = mapOf("tap" to setOf("x"))),
                    config,
                )
            }
        }

    @Test
    fun `updateToolPermissionsConfig coerces denylist-shaped config to deny all on hardened build`() =
        testScope.runTest {
            repository.updateToolPermissionsConfig(ToolPermissionsConfig(disabledTools = setOf("tap")))
            val config = repository.getServerConfig().toolPermissionsConfig
            assertFalse(config.isToolEnabled("tap"))
            if (BuildConfig.LAB_HARDENED) {
                // A denylist-shaped document would fail hardened parsing on the next load,
                // so the persisted document is normalized to the versioned deny-by-default
                // policy while the explicit denials stay ANDed with the empty allowlist.
                assertEquals(
                    ToolPermissionsConfig(
                        disabledTools = setOf("tap"),
                        allowedToolIds = emptySet(),
                    ),
                    config,
                )
                assertEquals(
                    """{"schemaVersion":1,"allowedToolIds":[],"disabledParams":{},"disabledTools":["tap"]}""",
                    storedPolicyJson(),
                )
            } else {
                assertEquals(ToolPermissionsConfig(disabledTools = setOf("tap")), config)
            }
        }

    @Test
    fun `updateToolEnabled builds the allowlist and persists the hardened document`() =
        testScope.runTest {
            repository.updateToolEnabled("tap", true)
            val config = repository.getServerConfig().toolPermissionsConfig
            assertTrue(config.isToolEnabled("tap"))
            if (BuildConfig.LAB_HARDENED) {
                // Every other tool stays denied through the persisted allowlist.
                assertFalse(config.isToolEnabled("swipe"))
                assertEquals(
                    """{"schemaVersion":1,"allowedToolIds":["tap"],"disabledParams":{},"disabledTools":[]}""",
                    storedPolicyJson(),
                )
            } else {
                // Upstream fallback: tap was already enabled, so the denylist is unchanged
                // and the other tool keeps the all-enabled default.
                assertTrue(config.isToolEnabled("swipe"))
                assertEquals("""{"disabledTools":[],"disabledParams":{}}""", storedPolicyJson())
            }
        }

    @Test
    fun `updateToolEnabled denies through the mode-specific mechanism`() =
        testScope.runTest {
            repository.updateToolEnabled("swipe", false)
            val config = repository.getServerConfig().toolPermissionsConfig
            assertFalse(config.isToolEnabled("swipe"))
            if (BuildConfig.LAB_HARDENED) {
                // The empty allowlist denies every tool.
                assertFalse(config.isToolEnabled("tap"))
            } else {
                assertTrue(config.isToolEnabled("tap"))
            }
        }

    @Test
    fun `updateParamEnabled persists disabled params in both policy modes`() =
        testScope.runTest {
            repository.updateParamEnabled("get_screen_state", "include_screenshot", false)
            val config = repository.getServerConfig().toolPermissionsConfig
            assertFalse(config.isParamEnabled("get_screen_state", "include_screenshot"))
            assertTrue(storedPolicyJson()!!.contains("include_screenshot"))
        }
}
