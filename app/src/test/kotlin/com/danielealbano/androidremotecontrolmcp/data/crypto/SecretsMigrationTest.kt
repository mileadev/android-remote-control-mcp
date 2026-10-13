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
import com.danielealbano.androidremotecontrolmcp.data.repository.MAX_SECRET_MIGRATION_FAILURES
import com.danielealbano.androidremotecontrolmcp.data.repository.SECRET_MIGRATION_FAILURES_KEY
import com.danielealbano.androidremotecontrolmcp.data.repository.SettingsChangeLogger
import com.danielealbano.androidremotecontrolmcp.data.repository.SettingsRepositoryImpl
import com.danielealbano.androidremotecontrolmcp.testutil.RecordingServerLogRepository
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
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
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit

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

    /** A new repository over the same store: what a process restart looks like from here. */
    private fun relaunch() {
        repository =
            SettingsRepositoryImpl(
                dataStore,
                changeLogger,
                EventChannelSettingsImpl(dataStore, changeLogger),
                secretCipher,
            )
    }

    private suspend fun rawMigrationFailures(): Int = dataStore.data.first()[SECRET_MIGRATION_FAILURES_KEY] ?: 0

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
    @DisplayName("bounded retry of an unusable key")
    inner class BoundedRetryOfAnUnusableKey {
        @Test
        fun `a spent budget stops the retries, keeps the app callable and refuses the plaintext`() =
            testScope.runTest {
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
                secretCipher.makeKeyUnavailable()

                repeat(MAX_SECRET_MIGRATION_FAILURES - 1) { launchIndex ->
                    val attempt = runCatching { repository.ensureAuthModelMigrated() }
                    assertTrue(attempt.isFailure, "launch ${launchIndex + 1} must stay loud")
                    assertTrue(attempt.exceptionOrNull() is SecretCipherException)
                    // The several callers inside one launch (app start, both settings screens,
                    // every settings read) retry, but they share the launch's single failure.
                    assertTrue(runCatching { repository.getServerConfig() }.isFailure)
                    assertEquals(launchIndex + 1, rawMigrationFailures())
                    relaunch()
                }
                assertEquals(MAX_SECRET_MIGRATION_FAILURES - 1, rawMigrationFailures())

                // Spends the budget's last launch; the abandon itself must not throw.
                repository.ensureAuthModelMigrated()

                assertEquals(MAX_SECRET_MIGRATION_FAILURES, rawMigrationFailures())
                // Abandoned: no further retry, no further write, and the app is callable again.
                repository.ensureAuthModelMigrated()
                assertEquals(MAX_SECRET_MIGRATION_FAILURES, rawMigrationFailures())

                assertEquals("", repository.getServerConfig().bearerToken)
                assertEquals(
                    "legacy-bearer-value-1",
                    raw(BEARER_KEY),
                    "a refused plaintext must be left in place, not deleted",
                )

                flushChangeLogger()
                val settingsMessages = serverLogRepository.ofType(ServerLogEntry.Type.SETTINGS).map { it.message }
                assertTrue(
                    settingsMessages.any { it.contains("Secret-at-rest migration abandoned") },
                    "an abandoned migration must be recorded for the operator",
                )
                assertLogsCarryNoSecretValues(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
            }

        @Test
        fun `concurrent callers of one launch record a single failure`() =
            testScope.runTest {
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
                secretCipher.makeKeyUnavailable()

                // The application starts the migration on its own IO coroutine and a settings
                // screen starts the same work; only the first of them may spend the launch's
                // attempt, so they are released together on real threads. This detects a revert
                // of the atomic claim with high probability rather than by construction: a
                // non-atomic field would have to be caught inside its read-to-write window,
                // which sixteen simultaneous callers do reliably in practice, not provably.
                val start = CyclicBarrier(CONCURRENT_CALLERS)
                val attempts =
                    (1..CONCURRENT_CALLERS)
                        .map {
                            async(Dispatchers.IO) {
                                start.await(START_BARRIER_TIMEOUT_S, TimeUnit.SECONDS)
                                runCatching { repository.ensureAuthModelMigrated() }
                            }
                        }.awaitAll()

                assertTrue(attempts.all { it.isFailure }, "every concurrent caller must stay loud")
                assertEquals(1, rawMigrationFailures(), "one failing launch must record one failure")
            }

        @Test
        fun `a transient failure stays recoverable and a completed migration clears the budget`() =
            testScope.runTest {
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
                secretCipher.makeKeyUnavailable()

                val failed = runCatching { repository.ensureAuthModelMigrated() }
                assertTrue(failed.isFailure)
                assertEquals(1, rawMigrationFailures())

                // While a failure is on record the at-rest transform is not trusted:
                // the direct read path refuses the unmigrated value instead of releasing it.
                assertEquals("", repository.serverConfig.first().bearerToken)

                secretCipher.restoreKey()
                repository.ensureAuthModelMigrated()

                assertTrue(isSecretEnvelope(raw(BEARER_KEY)!!))
                assertEquals(0, rawMigrationFailures(), "a completed migration clears the retry budget")
                assertEquals("legacy-bearer-value-1", repository.getServerConfig().bearerToken)
            }

        @Test
        fun `an abandoned install probes once per launch so a keystore that comes back is used`() =
            testScope.runTest {
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
                secretCipher.makeKeyUnavailable()
                repeat(MAX_SECRET_MIGRATION_FAILURES) {
                    runCatching { repository.ensureAuthModelMigrated() }
                    relaunch()
                }
                assertEquals(MAX_SECRET_MIGRATION_FAILURES, rawMigrationFailures())
                assertEquals("", repository.getServerConfig().bearerToken)

                // The key works again (restored backup, unlocked keystore). The next launch probes
                // once, so the install heals by itself instead of being dead for good.
                secretCipher.restoreKey()
                relaunch()
                repository.ensureAuthModelMigrated()

                assertEquals(0, rawMigrationFailures(), "a healed key must clear the spent budget")
                assertTrue(isSecretEnvelope(raw(BEARER_KEY)!!))
                assertEquals("legacy-bearer-value-1", repository.getServerConfig().bearerToken)
            }

        @Test
        fun `a pass-through flavor neither inherits the budget nor loses its plaintext secrets`() =
            testScope.runTest {
                seedLegacyPlaintexts(
                    "legacy-bearer-value-1",
                    "legacy-jwt-value-1",
                    "legacy-ngrok-value-1",
                    "legacy-cloudflare-value-1",
                )
                secretCipher.makeKeyUnavailable()
                repeat(MAX_SECRET_MIGRATION_FAILURES) {
                    runCatching { repository.ensureAuthModelMigrated() }
                    relaunch()
                }
                assertEquals(MAX_SECRET_MIGRATION_FAILURES, rawMigrationFailures())

                // Same app data, a flavor that performs no at-rest transform (debug builds).
                repository =
                    SettingsRepositoryImpl(
                        dataStore,
                        changeLogger,
                        EventChannelSettingsImpl(dataStore, changeLogger),
                        PlaintextSecretCipher,
                    )

                // The inherited counter must not suppress the reads this flavor is documented for.
                assertEquals("legacy-bearer-value-1", repository.serverConfig.first().bearerToken)

                repository.ensureAuthModelMigrated()

                assertEquals(0, rawMigrationFailures(), "a pass-through flavor must not carry the budget")
                assertEquals("legacy-bearer-value-1", repository.getServerConfig().bearerToken)
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

        const val CONCURRENT_CALLERS = 16
        const val START_BARRIER_TIMEOUT_S = 30L
    }
}
