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
import io.mockk.verify
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
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
@DisplayName("Secrets at rest on hardened builds (H-06)")
class LabSecretsAtRestTest {
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
            produceFile = { File(tempDir, "test_secrets_at_rest_$testFileCounter.preferences_pb") },
        )

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

    private fun assertIntegrityRefusalWasLogged() {
        verify {
            Log.w(
                eq("MCP:SettingsRepo"),
                withArg<String> { message ->
                    assertTrue(
                        message.contains("at-rest integrity verification; refusing to release it"),
                        "integrity failures must be logged without secret values",
                    )
                },
            )
        }
    }

    @Nested
    @DisplayName("encrypted at rest for every secret channel")
    inner class EncryptedAtRestPosture {
        @Test
        fun `bearer updates persist envelopes and read back the original value`() =
            testScope.runTest {
                repository.updateBearerToken("secret-bearer-value-1")

                assertTrue(isSecretEnvelope(raw(BEARER_KEY)!!), "bearer must persist as an envelope")
                assertEquals("secret-bearer-value-1", repository.getServerConfig().bearerToken)
                flushChangeLogger()
                assertLogsCarryNoSecretValues("secret-bearer-value-1")
            }

        @Test
        fun `hardened build refuses to persist tunnel credentials`() =
            testScope.runTest {
                assumeTrue(BuildConfig.LAB_HARDENED, "tunnel secrecy is hardened-only")

                repository.updateNgrokAuthtoken("secret-ngrok-value-1")
                repository.updateCloudflareTunnelToken("secret-cloudflare-value-1")

                assertNull(raw(NGROK_KEY), "ngrok authtoken must not be persistable")
                assertNull(raw(CLOUDFLARE_KEY), "Cloudflare tunnel token must not be persistable")
                assertEquals("", repository.getServerConfig().ngrokAuthtoken)
                assertEquals("", repository.getServerConfig().cloudflareTunnelToken)
                flushChangeLogger()
                val settingsMessages = serverLogRepository.ofType(ServerLogEntry.Type.SETTINGS).map { it.message }
                assertTrue(settingsMessages.any { it.contains("not persisted") })
                assertLogsCarryNoSecretValues("secret-ngrok-value-1", "secret-cloudflare-value-1")
            }

        @Test
        fun `other flavors keep persisting tunnel credentials`() =
            testScope.runTest {
                assumeFalse(BuildConfig.LAB_HARDENED, "tunnel persistence is only stripped on hardened builds")
                testFileCounter++
                val upstreamStore = newDataStore()
                val upstreamRepository =
                    SettingsRepositoryImpl(
                        upstreamStore,
                        changeLogger,
                        EventChannelSettingsImpl(upstreamStore, changeLogger),
                        PlaintextSecretCipher,
                    )

                upstreamRepository.updateNgrokAuthtoken("secret-ngrok-value-1")
                upstreamRepository.updateCloudflareTunnelToken("secret-cloudflare-value-1")

                assertEquals(
                    "secret-ngrok-value-1",
                    upstreamStore.data.first()[NGROK_KEY],
                    "existing flavors keep upstream plaintext persistence",
                )
                assertEquals("secret-cloudflare-value-1", upstreamStore.data.first()[CLOUDFLARE_KEY])
                assertEquals("secret-ngrok-value-1", upstreamRepository.getServerConfig().ngrokAuthtoken)
                assertEquals(
                    "secret-cloudflare-value-1",
                    upstreamRepository.getServerConfig().cloudflareTunnelToken,
                )
            }

        @Test
        fun `jwt secret is generated once and stored as an envelope`() =
            testScope.runTest {
                val first = repository.getOrCreateJwtSigningSecret()

                assertTrue(isSecretEnvelope(raw(JWT_KEY)!!), "jwt secret must persist as an envelope")
                assertEquals(first, repository.getOrCreateJwtSigningSecret())
                assertFalse(first.isEmpty())
            }
    }

    @Nested
    @DisplayName("fail-closed reads never leak or reset stored secrets")
    inner class FailClosedReads {
        @Test
        fun `a corrupt envelope reads as empty and leaves the stored value intact`() =
            testScope.runTest {
                val intact = secretCipher.encrypt("secret-bearer-value-1")
                dataStore.edit { prefs -> prefs[BEARER_KEY] = tamperSecretEnvelope(intact) }

                assertEquals("", repository.getServerConfig().bearerToken)

                assertEquals(
                    tamperSecretEnvelope(intact),
                    raw(BEARER_KEY),
                    "integrity failures must not clear the store",
                )
                assertIntegrityRefusalWasLogged()
                flushChangeLogger()
                assertLogsCarryNoSecretValues("secret-bearer-value-1", intact)
            }

        @Test
        fun `a body shorter than the authentication tag reads as empty and is not cleared`() =
            testScope.runTest {
                val intact = secretCipher.encrypt("secret-bearer-value-1")
                val truncated = truncateSecretEnvelope(intact)
                dataStore.edit { prefs -> prefs[BEARER_KEY] = truncated }

                assertEquals("", repository.getServerConfig().bearerToken)

                assertEquals(truncated, raw(BEARER_KEY), "integrity failures must not clear the store")
                assertIntegrityRefusalWasLogged()
            }

        @Test
        fun `an invalidated key renders stored bearer data unusable without clearing it`() =
            testScope.runTest {
                repository.updateBearerToken("secret-bearer-value-1")
                val envelope = raw(BEARER_KEY)!!
                secretCipher.rotateKey()

                assertEquals("", repository.getServerConfig().bearerToken)

                assertEquals(envelope, raw(BEARER_KEY), "invalidated keys must not clear the store")
                assertIntegrityRefusalWasLogged()
            }

        @Test
        fun `an invalidated key makes jwt issuance fail loudly instead of regenerating`() =
            testScope.runTest {
                val original = repository.getOrCreateJwtSigningSecret()
                val envelope = raw(JWT_KEY)!!
                secretCipher.rotateKey()

                val attempt = runCatching { repository.getOrCreateJwtSigningSecret() }
                assertTrue(attempt.isFailure)
                assertTrue(attempt.exceptionOrNull() is SecretCipherException)

                assertEquals(envelope, raw(JWT_KEY), "jwt issuance failure must not clear the store")
                assertFalse(original.isEmpty())
            }
    }

    @Nested
    @DisplayName("envelopes survive a repository restart")
    inner class PersistenceAcrossInstances {
        @Test
        fun `a fresh instance decrypts the durable envelopes of a previous process`() =
            testScope.runTest {
                repository.updateBearerToken("secret-bearer-value-1")
                val jwtSecret = repository.getOrCreateJwtSigningSecret()

                testFileCounter++
                val restartedStore = newDataStore()
                restartedStore.edit { prefs ->
                    prefs[BEARER_KEY] = raw(BEARER_KEY)!!
                    prefs[JWT_KEY] = raw(JWT_KEY)!!
                }
                val restartedRepository =
                    SettingsRepositoryImpl(
                        restartedStore,
                        changeLogger,
                        EventChannelSettingsImpl(restartedStore, changeLogger),
                        secretCipher,
                    )

                assertEquals("secret-bearer-value-1", restartedRepository.getServerConfig().bearerToken)
                assertEquals(jwtSecret, restartedRepository.getOrCreateJwtSigningSecret())
            }
    }

    private companion object {
        val BEARER_KEY = stringPreferencesKey("bearer_token")
        val JWT_KEY = stringPreferencesKey("jwt_signing_secret")
        val NGROK_KEY = stringPreferencesKey("ngrok_authtoken")
        val CLOUDFLARE_KEY = stringPreferencesKey("cloudflare_tunnel_token")
    }
}
