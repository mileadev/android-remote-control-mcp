package com.danielealbano.androidremotecontrolmcp.startup

import android.util.Log
import com.danielealbano.androidremotecontrolmcp.data.crypto.SecretCipherException
import com.danielealbano.androidremotecontrolmcp.data.repository.SettingsRepository
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("applyAuthModelMigration")
class AuthModelMigrationTest {
    private lateinit var settingsRepository: SettingsRepository

    @BeforeEach
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.w(any<String>(), any<String>(), any()) } returns 0
        settingsRepository = mockk(relaxed = true)
    }

    @AfterEach
    fun tearDown() = unmockkStatic(Log::class)

    @Test
    @DisplayName("applies the migration exactly once when it succeeds")
    fun appliesMigration() =
        runTest {
            applyAuthModelMigration(settingsRepository)

            coVerify(exactly = 1) { settingsRepository.ensureAuthModelMigrated() }
            verify(exactly = 0) { Log.w(any<String>(), any<String>(), any()) }
        }

    // Both failure tests rely on reaching their assertions at all: with the guard removed the call
    // throws and the test fails, which is the drift they are here to catch.

    @Test
    @DisplayName("an unusable at-rest key is logged and does not escape the caller")
    fun unusableKeyIsLoggedNotThrown() =
        runTest {
            coEvery { settingsRepository.ensureAuthModelMigrated() } throws
                SecretCipherException("at-rest key is unavailable")

            applyAuthModelMigration(settingsRepository)

            verify(exactly = 1) { Log.w(any<String>(), any<String>(), any()) }
        }

    @Test
    @DisplayName("any other migration failure is contained too")
    fun otherFailuresAreContained() =
        runTest {
            coEvery { settingsRepository.ensureAuthModelMigrated() } throws
                IllegalStateException("DataStore is unreadable")

            applyAuthModelMigration(settingsRepository)

            verify(exactly = 1) { Log.w(any<String>(), any<String>(), any()) }
        }
}
