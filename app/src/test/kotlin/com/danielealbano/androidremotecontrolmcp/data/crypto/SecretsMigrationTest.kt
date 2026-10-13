package com.danielealbano.androidremotecontrolmcp.data.crypto

import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.data.model.ServerLogEntry
import com.danielealbano.androidremotecontrolmcp.data.repository.EventChannelSettingsImpl
import com.danielealbano.androidremotecontrolmcp.data.repository.SettingsChangeLogger
import com.danielealbano.androidremotecontrolmcp.data.repository.SettingsRepositoryImpl
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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("Secrets at-rest migration (H-06)")
class SecretsMigrationTest {
    @TempDir
    lateinit var tempDir: File

    private val testDispatcher = UnconfinedTestDispatcher()
    private val testScope = TestScope(testDispatcher)

    private val serverLogRepository = RecordingServerLogRepository()
    private val secretCipher = FakeSecretCipher()

    private lateinit var dataStore: DataStore<Preferences>
    private lateinit var repository: SettingsRepositoryImpl
    private lateinit var changeLogger: SettingsChangeLogger

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
        dataStore = newDataStore()
        changeLogger =
            SettingsChangeLogger(
                serverLogRepository,
                testDispatcher,
                SettingsChangeLogger.COALESCE_WINDOW_MS,
            )
        repository =
            SettingsRepositoryImpl(
                dataStore,
                changeLogger,
                EventChannelSettingsImpl(dataStore, changeLogger),
                secretCipher,
            )
    }

    @AfterEach
    fun tearDown() {
        unmockkStatic(Log::class)
    }

    private fun newDataStore(): DataStore<Preferences> =
        PreferenceDataStoreFactory.create(
            scope = testScope.backgroundScope,
            produceFile = { File(tempDir, "test_secrets_migration_$testFileCounter.preferences_pb") },
        )

    private suspend fun seedLegacyPlaintexts(
        bearer: String,
        jwt: String,
        ngrok: String,
        cloudflare: String,
    ) {
        dataStore.edit { prefs ->
            prefs[BEARER_KEY] = bearer
            prefs[JWT_KEY] = jwt
            prefs[NGROK_KEY] = ngrok
            prefs[CLOUDFLARE_KEY] = cloudflare
        }
    }

    private suspend fun raw(key: Preferences.Key<String>): String? = dataStore.data.first()[key]

    private suspend fun flushChangeLogger() {
        testScope.testScheduler.advanceTimeBy(SettingsChangeLogger.COALESCE_WINDOW_MS + 1L)
    }

    private fun assertLogsCarryNoSecretValues(vararg forbidden: String) {
        val messages = serverLogRepository.entries.joinToString("\n") { it.message }
        forbidden.forEach { value ->
            assertTrue(!messages.contains(value), "a log entry carries a secret value")
        }
        assertTrue(!messages.contains(SECRET_ENVELOPE_PREFIX), "a log entry carries an envelope")
    }

    @Nested
    @DisplayName("authenticated migration of legacy plaintext")
    inner class LegacyPlaintextMigration {
        @Test
        fun `legacy plaintexts become envelopes whose reads return the original values`() =
            testScope.runTest {
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )

                repository.ensureAuthModelMigrated()

                assertTrue(isSecretEnvelope(raw(BEARER_KEY)!!))
                assertTrue(isSecretEnvelope(raw(JWT_KEY)!!))
                if (BuildConfig.LAB_HARDENED) {
                    assertNull(raw(NGROK_KEY), "hardened build must drop tunnel secrets")
                    assertNull(raw(CLOUDFLARE_KEY), "hardened build must drop tunnel secrets")
                } else {
                    assertTrue(isSecretEnvelope(raw(NGROK_KEY)!!))
                    assertTrue(isSecretEnvelope(raw(CLOUDFLARE_KEY)!!))
                }
                assertEquals("legacy-bearer-value-1", repository.getServerConfig().bearerToken)
                assertLogsCarryNoSecretValues(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
            }

        @Test
        fun `migration is idempotent and never re-encrypts envelopes`() =
            testScope.runTest {
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
                repository.ensureAuthModelMigrated()
                val firstEnvelope = raw(BEARER_KEY)!!

                repository.ensureAuthModelMigrated()

                assertEquals(firstEnvelope, raw(BEARER_KEY), "idempotent migration must keep the original envelope")
            }

        @Test
        fun `hardened build drops persistable tunnel secrets during migration`() =
            testScope.runTest {
                assumeTrue(BuildConfig.LAB_HARDENED, "tunnel-drop behavior is hardened-only")
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )

                repository.ensureAuthModelMigrated()

                assertNull(raw(NGROK_KEY))
                assertNull(raw(CLOUDFLARE_KEY))
                assertEquals("", repository.getServerConfig().ngrokAuthtoken)
                assertEquals("", repository.getServerConfig().cloudflareTunnelToken)
                flushChangeLogger()
                val settingsMessages = serverLogRepository.ofType(ServerLogEntry.Type.SETTINGS).map { it.message }
                assertTrue(
                    settingsMessages.any { it.contains("Tunnel credentials not persisted") },
                    "the tunnel-secret drop must be signaled without values",
                )
                assertLogsCarryNoSecretValues("legacy-ngrok-value-1", "legacy-cloudflare-value-1")
            }

        @Test
        fun `other flavors keep tunnel secrets through migration`() =
            testScope.runTest {
                assumeFalse(BuildConfig.LAB_HARDENED, "tunnel persistence is only stripped on hardened builds")
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )

                repository.ensureAuthModelMigrated()

                assertTrue(isSecretEnvelope(raw(NGROK_KEY)!!))
                assertTrue(isSecretEnvelope(raw(CLOUDFLARE_KEY)!!))
                assertEquals("legacy-ngrok-value-1", repository.getServerConfig().ngrokAuthtoken)
            }

        @Test
        fun `pass-through cipher leaves legacy plaintexts untouched`() =
            testScope.runTest {
                testFileCounter++
                val plaintextDataStore = newDataStore()
                plaintextDataStore.edit { prefs -> prefs[BEARER_KEY] = "legacy-bearer-value-1" }
                val plaintextRepository =
                    SettingsRepositoryImpl(
                        plaintextDataStore,
                        changeLogger,
                        EventChannelSettingsImpl(plaintextDataStore, changeLogger),
                        PlaintextSecretCipher,
                    )

                plaintextRepository.ensureAuthModelMigrated()

                assertEquals("legacy-bearer-value-1", plaintextDataStore.data.first()[BEARER_KEY])
                assertEquals("legacy-bearer-value-1", plaintextRepository.getServerConfig().bearerToken)
            }
    }

    @Nested
    @DisplayName("atomicity under key failure")
    inner class AtomicityUnderKeyFailure {
        @Test
        fun `an unavailable key aborts migration leaving plaintext intact`() =
            testScope.runTest {
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
                secretCipher.makeKeyUnavailable()

                val attempt = runCatching { repository.ensureAuthModelMigrated() }
                assertTrue(attempt.isFailure)
                assertTrue(attempt.exceptionOrNull() is SecretCipherException)

                assertEquals("legacy-bearer-value-1", raw(BEARER_KEY), "failed migration must not touch the plaintext")
                assertEquals("legacy-jwt-value-1", raw(JWT_KEY))

                secretCipher.restoreKey()
                repository.ensureAuthModelMigrated()
                assertTrue(isSecretEnvelope(raw(BEARER_KEY)!!))
                assertEquals("legacy-bearer-value-1", repository.getServerConfig().bearerToken)
            }

        @Test
        fun `jwt bootstrap migration failure leaves the legacy value intact`() =
            testScope.runTest {
                dataStore.edit { prefs -> prefs[JWT_KEY] = "legacy-jwt-value-1" }
                secretCipher.makeKeyUnavailable()

                val attempt = runCatching { repository.getOrCreateJwtSigningSecret() }
                assertTrue(attempt.isFailure)
                assertTrue(attempt.exceptionOrNull() is SecretCipherException)
                assertEquals("legacy-jwt-value-1", raw(JWT_KEY), "failed migration must not touch the plaintext")

                secretCipher.restoreKey()
                assertEquals("legacy-jwt-value-1", repository.getOrCreateJwtSigningSecret())
            }
    }

    @Nested
    @DisplayName("no secrets in logs during migration and reads")
    inner class NoSecretsInLogs {
        @Test
        fun `writes, migration, and reads never log secret values`() =
            testScope.runTest {
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
                repository.ensureAuthModelMigrated()

                repository.updateBearerToken("secret-value-2")
                repository.getServerConfig()
                repository.getOrCreateJwtSigningSecret()

                flushChangeLogger()
                assertLogsCarryNoSecretValues("legacy-bearer-value-1", "secret-value-2", "legacy-jwt-value-1")
            }
    }

    private companion object {
        val BEARER_KEY = stringPreferencesKey("bearer_token")
        val JWT_KEY = stringPreferencesKey("jwt_signing_secret")
        val NGROK_KEY = stringPreferencesKey("ngrok_authtoken")
        val CLOUDFLARE_KEY = stringPreferencesKey("cloudflare_tunnel_token")
    }
}
