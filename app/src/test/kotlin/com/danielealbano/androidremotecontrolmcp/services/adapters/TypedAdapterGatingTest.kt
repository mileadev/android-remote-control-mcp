package com.danielealbano.androidremotecontrolmcp.services.adapters

import android.content.Context
import android.content.pm.PackageManager
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/** Fake adapter with fully controllable gating parameters. */
private class FakeFrameworkAdapter(
    override val supportedApiLevels: IntRange,
    override val requiredPermissions: List<String>,
    private val specMinApiLevel: Int,
    private val specPermissions: List<String> = emptyList(),
) : FrameworkAdapter {
    override val id: String = "fake-adapter"

    override val domain: String = "fake"

    override val actionSchemas: List<AdapterActionSpec> =
        listOf(
            AdapterActionSpec(
                actionId = FakeTestAction.ACTION_ID,
                description = "Fake action for gating tests",
                inputFields = mapOf("value" to AdapterFieldType.STRING),
                outputFields = emptyMap(),
                minApiLevel = specMinApiLevel,
                requiredPermissions = specPermissions,
            ),
        )

    override fun supports(action: AdapterAction): Boolean = action is FakeTestAction

    var dispatchCount: Int = 0

    override suspend fun dispatch(action: AdapterAction): AdapterOutcome {
        dispatchCount += 1
        return AdapterOutcome.Completed(detail = "fake-ok")
    }
}

private class FakeTestAction : AdapterAction {
    override val actionId: String get() = ACTION_ID

    companion object {
        const val ACTION_ID = "fake.test_action"
    }
}

@DisplayName("TypedAdapterGating")
class TypedAdapterGatingTest {
    private lateinit var context: Context

    private lateinit var platformVersion: PlatformVersionProvider

    @BeforeEach
    fun setUp() {
        context = mockk(relaxed = true)
        every { context.checkSelfPermission(any()) } returns PackageManager.PERMISSION_GRANTED
    }

    @AfterEach
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `refuses api levels below the adapter range with typed failure`() =
        runTest {
            platformVersion = FixedApiLevelProvider(31)
            val fake = FakeFrameworkAdapter(33..37, emptyList(), 33)
            val registry = FrameworkAdapterRegistry(listOf(fake), platformVersion, context)

            val outcome = registry.dispatch(FakeTestAction())

            assertTrue(outcome is AdapterOutcome.Rejected)
            val rejection = (outcome as AdapterOutcome.Rejected).rejection
            assertTrue(rejection is AdapterRejection.UnsupportedApiLevel)
            rejection as AdapterRejection.UnsupportedApiLevel
            assertEquals(33..37, rejection.supportedApiLevels)
            assertEquals(31, rejection.actualApiLevel)
            assertEquals("fake-adapter", rejection.adapterId)
            assertEquals(0, fake.dispatchCount)
        }

    @Test
    fun `refuses api levels above the adapter range with typed failure`() =
        runTest {
            platformVersion = FixedApiLevelProvider(38)
            val fake = FakeFrameworkAdapter(33..37, emptyList(), 33)
            val registry = FrameworkAdapterRegistry(listOf(fake), platformVersion, context)

            val outcome = registry.dispatch(FakeTestAction())

            assertTrue((outcome as AdapterOutcome.Rejected).rejection is AdapterRejection.UnsupportedApiLevel)
            assertEquals(0, fake.dispatchCount)
        }

    @Test
    fun `refuses actions whose schema min api exceeds device api`() =
        runTest {
            platformVersion = FixedApiLevelProvider(34)
            val fake = FakeFrameworkAdapter(21..40, emptyList(), 35)
            val registry = FrameworkAdapterRegistry(listOf(fake), platformVersion, context)

            val outcome = registry.dispatch(FakeTestAction())

            val rejection = (outcome as AdapterOutcome.Rejected).rejection
            assertTrue(rejection is AdapterRejection.ActionRequiresNewerApi)
            rejection as AdapterRejection.ActionRequiresNewerApi
            assertEquals(FakeTestAction.ACTION_ID, rejection.actionId)
            assertEquals(35, rejection.minApiLevel)
            assertEquals(34, rejection.actualApiLevel)
            assertEquals(0, fake.dispatchCount)
        }

    @Test
    fun `refuses flags newer than device api with typed feature failure`() =
        runTest {
            platformVersion = FixedApiLevelProvider(33)
            val adapter = IntentFrameworkAdapter(context, platformVersion)
            val registry = FrameworkAdapterRegistry(listOf(adapter), platformVersion, context)

            val outcome =
                registry.dispatch(
                    IntentFrameworkAction.DispatchIntent(
                        delivery = IntentFrameworkAction.Delivery.BROADCAST,
                        intentAction = "com.example.ACTION",
                        dataUri = null,
                        component = null,
                        packageName = null,
                        extras = emptyMap(),
                        flags =
                            listOf(
                                IntentFlagCatalog.FLAG_INCLUDE_STOPPED_PACKAGES,
                                IntentFlagCatalog.FLAG_ACTIVITY_REQUIRE_DEFAULT,
                            ),
                    ),
                )

            val rejection = (outcome as AdapterOutcome.Rejected).rejection
            assertTrue(rejection is AdapterRejection.FeatureRequiresNewerApi)
            rejection as AdapterRejection.FeatureRequiresNewerApi
            assertEquals("FLAG_ACTIVITY_REQUIRE_DEFAULT", rejection.feature)
            assertEquals(34, rejection.minApiLevel)
            assertEquals(33, rejection.actualApiLevel)
        }

    @Test
    fun `refuses dispatch when declared permissions are missing`() =
        runTest {
            platformVersion = FixedApiLevelProvider(34)
            every { context.checkSelfPermission(any()) } returns PackageManager.PERMISSION_DENIED
            val fake = FakeFrameworkAdapter(21..40, listOf("android.permission.FAKE"), 21)
            val registry = FrameworkAdapterRegistry(listOf(fake), platformVersion, context)

            val outcome = registry.dispatch(FakeTestAction())

            val rejection = (outcome as AdapterOutcome.Rejected).rejection
            assertTrue(rejection is AdapterRejection.MissingPermissions)
            rejection as AdapterRejection.MissingPermissions
            assertEquals(listOf("android.permission.FAKE"), rejection.permissions)
            assertEquals(0, fake.dispatchCount)
        }

    @Test
    fun `unions adapter and action permissions for the permission gate`() =
        runTest {
            platformVersion = FixedApiLevelProvider(34)
            every { context.checkSelfPermission(any()) } returns PackageManager.PERMISSION_DENIED
            val fake =
                FakeFrameworkAdapter(
                    21..40,
                    listOf("android.permission.FAKE"),
                    21,
                    specPermissions = listOf("android.permission.FAKE_ACTION_PERMISSION"),
                )
            val registry = FrameworkAdapterRegistry(listOf(fake), platformVersion, context)

            val outcome = registry.dispatch(FakeTestAction())

            val rejection = (outcome as AdapterOutcome.Rejected).rejection as AdapterRejection.MissingPermissions
            assertEquals(
                listOf("android.permission.FAKE", "android.permission.FAKE_ACTION_PERMISSION").sorted(),
                rejection.permissions.sorted(),
            )
            assertEquals(0, fake.dispatchCount)
        }

    @Test
    fun `dispatches when permissions granted`() =
        runTest {
            platformVersion = FixedApiLevelProvider(34)
            val fake = FakeFrameworkAdapter(21..40, listOf("android.permission.FAKE"), 21)
            val registry = FrameworkAdapterRegistry(listOf(fake), platformVersion, context)

            val outcome = registry.dispatch(FakeTestAction())

            assertTrue(outcome is AdapterOutcome.Completed)
            assertEquals(1, fake.dispatchCount)
        }

    @Test
    fun `refuses unknown actions listing every adapter schema`() =
        runTest {
            platformVersion = FixedApiLevelProvider(34)
            val adapter = IntentFrameworkAdapter(context, platformVersion)
            val registry = FrameworkAdapterRegistry(listOf(adapter), platformVersion, context)

            val outcome =
                registry.dispatch(
                    object : AdapterAction {
                        override val actionId: String get() = "unknown.action"
                    },
                )

            val rejection = (outcome as AdapterOutcome.Rejected).rejection
            assertTrue(rejection is AdapterRejection.UnknownAction)
            rejection as AdapterRejection.UnknownAction
            assertEquals("unknown.action", rejection.actionId)
            assertEquals(
                listOf(
                    IntentFrameworkAction.DispatchIntent.ACTION_ID,
                    IntentFrameworkAction.OpenUri.ACTION_ID,
                ),
                rejection.supportedActionIds,
            )
        }

    @Test
    fun `real adapter refuses below its declared self range even when registry passes`() =
        runTest {
            // Registry gate intentionally relies on the adapter self-gate too.
            platformVersion = FixedApiLevelProvider(31)
            val adapter = IntentFrameworkAdapter(context, platformVersion)
            val registry = FrameworkAdapterRegistry(listOf(adapter), platformVersion, context)

            val outcome =
                registry.dispatch(
                    IntentFrameworkAction.OpenUri(uri = "content://test", packageName = null, mimeType = null),
                )

            val rejection = (outcome as AdapterOutcome.Rejected).rejection
            assertTrue(rejection is AdapterRejection.UnsupportedApiLevel)
            assertEquals(31, (rejection as AdapterRejection.UnsupportedApiLevel).actualApiLevel)
        }

    @Test
    fun `real adapter dispatches broadcast at api 34`() =
        runTest {
            platformVersion = FixedApiLevelProvider(34)
            val adapter = IntentFrameworkAdapter(context, platformVersion)
            val registry = FrameworkAdapterRegistry(listOf(adapter), platformVersion, context)

            val outcome =
                registry.dispatch(
                    IntentFrameworkAction.DispatchIntent(
                        delivery = IntentFrameworkAction.Delivery.BROADCAST,
                        intentAction = "com.example.ACTION",
                        dataUri = null,
                        component = null,
                        packageName = null,
                        extras = emptyMap(),
                        flags = emptyList(),
                    ),
                )

            assertTrue(outcome is AdapterOutcome.Completed)
            verify { context.sendBroadcast(any()) }
        }

    @Test
    fun `rejections describe themselves with actionable messages`() {
        val apiLevel = AdapterRejection.UnsupportedApiLevel("intent-framework", 33..37, 31)
        assertTrue(apiLevel.describe().contains("does not support API level 31"))
        assertTrue(apiLevel.describe().contains("supported: 33..37"))

        val unknown = AdapterRejection.UnknownAction("x.y", listOf("a.b", "c.d"))
        assertTrue(unknown.describe().contains("Unknown action 'x.y'"))
        assertTrue(unknown.describe().contains("a.b"))

        val newerAction = AdapterRejection.ActionRequiresNewerApi("a.b", 35, 34)
        assertTrue(newerAction.describe().contains("requires API level 35"))

        val newerFeature = AdapterRejection.FeatureRequiresNewerApi("FLAG_X", 34, 33)
        assertTrue(newerFeature.describe().contains("'FLAG_X'"))

        val missing = AdapterRejection.MissingPermissions(listOf("p.b", "p.a"))
        assertEquals("Missing required permissions: p.a, p.b", missing.describe())

        assertFalse(missing.describe().isBlank())
    }
}
