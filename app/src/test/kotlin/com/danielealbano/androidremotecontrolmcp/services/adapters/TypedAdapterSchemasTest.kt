package com.danielealbano.androidremotecontrolmcp.services.adapters

import android.content.Context
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/** Deterministic platform version stub shared by adapter tests. */
internal class FixedApiLevelProvider(
    private val level: Int,
) : PlatformVersionProvider {
    override val currentApiLevel: Int get() = level
}

@DisplayName("TypedAdapterSchemas")
class TypedAdapterSchemasTest {
    private val adapter =
        IntentFrameworkAdapter(mockk<Context>(relaxed = true), FixedApiLevelProvider(34))

    @Test
    fun `adapter declares explicit schemas for every action`() {
        val schemaIds = adapter.actionSchemas.map { it.actionId }

        assertEquals(
            listOf(
                IntentFrameworkAction.DispatchIntent.ACTION_ID,
                IntentFrameworkAction.OpenUri.ACTION_ID,
            ),
            schemaIds,
        )
        adapter.actionSchemas.forEach { spec ->
            assertTrue(spec.inputFields.isNotEmpty(), "Action ${spec.actionId} must declare input fields")
            assertTrue(spec.description.isNotBlank(), "Action ${spec.actionId} must have a description")
        }
    }

    @Test
    fun `dispatch schema is explicit and typed`() {
        val spec = adapter.actionSchemas.first { it.actionId == IntentFrameworkAction.DispatchIntent.ACTION_ID }

        assertEquals(
            mapOf(
                "delivery" to AdapterFieldType.ENUM,
                "intentAction" to AdapterFieldType.STRING_NULLABLE,
                "dataUri" to AdapterFieldType.STRING_NULLABLE,
                "component" to AdapterFieldType.STRING_NULLABLE,
                "packageName" to AdapterFieldType.STRING_NULLABLE,
                "extras" to AdapterFieldType.STRING_VALUE_MAP,
                "flags" to AdapterFieldType.STRING_LIST,
            ),
            spec.inputFields,
        )
        assertEquals(listOf("ACTIVITY", "BROADCAST", "SERVICE"), spec.enumValues["delivery"])
        assertEquals(IntentFrameworkAdapter.MIN_API_LEVEL, spec.minApiLevel)
    }

    @Test
    fun `openUri schema is explicit and typed`() {
        val spec = adapter.actionSchemas.first { it.actionId == IntentFrameworkAction.OpenUri.ACTION_ID }

        assertEquals(
            mapOf(
                "uri" to AdapterFieldType.STRING,
                "packageName" to AdapterFieldType.STRING_NULLABLE,
                "mimeType" to AdapterFieldType.STRING_NULLABLE,
            ),
            spec.inputFields,
        )
        assertEquals(emptyMap<String, AdapterFieldType>(), spec.enumValues)
        assertEquals(emptyMap<String, AdapterFieldType>(), spec.outputFields)
    }

    @Test
    fun `adapter declares the supported platform version range`() {
        assertEquals(
            IntentFrameworkAdapter.MIN_API_LEVEL..IntentFrameworkAdapter.MAX_API_LEVEL,
            adapter.supportedApiLevels,
        )
        assertTrue(adapter.requiredPermissions.isEmpty(), "Intents require no Android permissions")
        assertEquals("intent-framework", adapter.id)
        assertEquals("intents", adapter.domain)
    }

    @Test
    fun `intent flag catalog covers the compile-time public flag set`() {
        val expectedFlags =
            setOf(
                "FLAG_ACTIVITY_BROUGHT_TO_FRONT",
                "FLAG_ACTIVITY_CLEAR_TASK",
                "FLAG_ACTIVITY_CLEAR_TOP",
                "FLAG_ACTIVITY_CLEAR_WHEN_TASK_RESET",
                "FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS",
                "FLAG_ACTIVITY_FORWARD_RESULT",
                "FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY",
                "FLAG_ACTIVITY_LAUNCH_ADJACENT",
                "FLAG_ACTIVITY_MATCH_EXTERNAL",
                "FLAG_ACTIVITY_MULTIPLE_TASK",
                "FLAG_ACTIVITY_NEW_DOCUMENT",
                "FLAG_ACTIVITY_NEW_TASK",
                "FLAG_ACTIVITY_NO_ANIMATION",
                "FLAG_ACTIVITY_NO_HISTORY",
                "FLAG_ACTIVITY_NO_USER_ACTION",
                "FLAG_ACTIVITY_PREVIOUS_IS_TOP",
                "FLAG_ACTIVITY_REQUIRE_DEFAULT",
                "FLAG_ACTIVITY_REQUIRE_NON_BROWSER",
                "FLAG_ACTIVITY_RESET_TASK_IF_NEEDED",
                "FLAG_ACTIVITY_RETAIN_IN_RECENTS",
                "FLAG_ACTIVITY_REORDER_TO_FRONT",
                "FLAG_ACTIVITY_SINGLE_TOP",
                "FLAG_ACTIVITY_TASK_ON_HOME",
                "FLAG_DEBUG_LOG_RESOLUTION",
                "FLAG_DIRECT_BOOT_AUTO",
                "FLAG_EXCLUDE_STOPPED_PACKAGES",
                "FLAG_FROM_BACKGROUND",
                "FLAG_GRANT_PERSISTABLE_URI_PERMISSION",
                "FLAG_GRANT_PREFIX_URI_PERMISSION",
                "FLAG_GRANT_READ_URI_PERMISSION",
                "FLAG_GRANT_WRITE_URI_PERMISSION",
                "FLAG_INCLUDE_STOPPED_PACKAGES",
                "FLAG_RECEIVER_FOREGROUND",
                "FLAG_RECEIVER_NO_ABORT",
                "FLAG_RECEIVER_REGISTERED_ONLY",
                "FLAG_RECEIVER_REPLACE_PENDING",
                "FLAG_RECEIVER_VISIBLE_TO_INSTANT_APPS",
            )

        assertEquals(expectedFlags, IntentFlagCatalog.entries.map { it.name }.toSet())
        assertEquals(expectedFlags.size, IntentFlagCatalog.entries.size, "Flag catalog must not contain duplicates")
        IntentFlagCatalog.entries.forEach { flag ->
            assertTrue(flag.name.startsWith("FLAG_"), "${flag.name} must be an Intent flag name")
            assertNotNull(IntentFlagCatalog.find(flag.name), "Round-trip lookup must resolve ${flag.name}")
        }
        // Upstream Intent historically aliases some values (e.g. FLAG_ACTIVITY_BROUGHT_TO_FRONT
        // shares FLAG_ACTIVITY_SINGLE_TOP); the catalog is keyed by name, so only names are unique.
    }

    @Test
    fun `flag catalog carries version gating data for platform-introduced flags`() {
        assertEquals(1, IntentFlagCatalog.FLAG_ACTIVITY_NEW_TASK.minApiLevel)
        assertEquals(12, IntentFlagCatalog.FLAG_INCLUDE_STOPPED_PACKAGES.minApiLevel)
        assertEquals(34, IntentFlagCatalog.FLAG_ACTIVITY_REQUIRE_DEFAULT.minApiLevel)
        assertEquals(34, IntentFlagCatalog.FLAG_ACTIVITY_REQUIRE_NON_BROWSER.minApiLevel)
    }

    @Test
    fun `unknown flag names are not resolvable`() {
        assertNull(IntentFlagCatalog.find("FLAG_NONEXISTENT"))
        assertNull(IntentFlagCatalog.find(""))
        assertNull(IntentFlagCatalog.find("android.intent.extra.FLAG"))
    }

    @Test
    fun `flag values match their compile-time Intent constants`() {
        assertEquals(android.content.Intent.FLAG_ACTIVITY_NEW_TASK, IntentFlagCatalog.FLAG_ACTIVITY_NEW_TASK.value)
        assertEquals(
            android.content.Intent.FLAG_INCLUDE_STOPPED_PACKAGES,
            IntentFlagCatalog.FLAG_INCLUDE_STOPPED_PACKAGES.value,
        )
        assertEquals(
            android.content.Intent.FLAG_ACTIVITY_REQUIRE_DEFAULT,
            IntentFlagCatalog.FLAG_ACTIVITY_REQUIRE_DEFAULT.value,
        )
    }

    @Test
    fun `extra inference keeps legacy type mapping`() {
        assertEquals(IntentExtraValue.Text("value"), IntentExtraValue.fromInferred("k", "value"))
        assertEquals(IntentExtraValue.Int32(42), IntentExtraValue.fromInferred("k", 42L))
        assertEquals(IntentExtraValue.Int64(9999999999L), IntentExtraValue.fromInferred("k", 9999999999L))
        assertEquals(IntentExtraValue.Int32(2), IntentExtraValue.fromInferred("k", 2.0))
        assertEquals(IntentExtraValue.Float64(3.14), IntentExtraValue.fromInferred("k", 3.14))
        assertEquals(IntentExtraValue.Bool(true), IntentExtraValue.fromInferred("k", true))
        assertEquals(
            IntentExtraValue.StringList(listOf("a", "b")),
            IntentExtraValue.fromInferred("k", listOf("a", "b")),
        )
        assertNull(IntentExtraValue.fromInferred("k", null))
    }

    @Test
    fun `extra inference refuses unsupported values with typed errors`() {
        val mapFailure =
            org.junit.jupiter.api.assertThrows<IllegalArgumentException> {
                IntentExtraValue.fromInferred("k", mapOf<Int, String>())
            }
        assertTrue(mapFailure.message?.contains("Cannot infer extra type for key 'k'") == true)

        val mixedListFailure =
            org.junit.jupiter.api.assertThrows<IllegalArgumentException> {
                IntentExtraValue.fromInferred("k", listOf("a", 1))
            }
        assertTrue(mixedListFailure.message?.contains("Cannot infer extra type for key 'k'") == true)

        val otherFailure =
            org.junit.jupiter.api.assertThrows<IllegalArgumentException> {
                IntentExtraValue.fromInferred("k", Any())
            }
        assertTrue(otherFailure.message?.contains("unsupported value type") == true)
    }

    @Test
    fun `extra overrides keep legacy conversion mapping`() {
        assertEquals(IntentExtraValue.Text("42"), IntentExtraValue.fromOverride("k", 42L, "string"))
        assertEquals(IntentExtraValue.Int32(7), IntentExtraValue.fromOverride("k", "7", "int"))
        assertEquals(IntentExtraValue.Int64(42L), IntentExtraValue.fromOverride("k", 42, "long"))
        assertEquals(IntentExtraValue.Float32(42.5f), IntentExtraValue.fromOverride("k", "42.5", "float"))
        assertEquals(IntentExtraValue.Float64(42.5), IntentExtraValue.fromOverride("k", "42.5", "double"))
        assertEquals(IntentExtraValue.Bool(true), IntentExtraValue.fromOverride("k", "true", "boolean"))
    }

    @Test
    fun `extra overrides refuse null values and unknown types with typed errors`() {
        val nullFailure =
            org.junit.jupiter.api.assertThrows<IllegalArgumentException> {
                IntentExtraValue.fromOverride("k", null, "string")
            }
        assertTrue(nullFailure.message?.contains("is null but type override") == true)

        val unsupportedFailure =
            org.junit.jupiter.api.assertThrows<IllegalArgumentException> {
                IntentExtraValue.fromOverride("k", "v", "unsupported")
            }
        assertTrue(unsupportedFailure.message?.contains("Unsupported extras_types value") == true)

        assertFalse(
            IntentExtraValue.fromOverride("k", "false", "boolean") == IntentExtraValue.Bool(true),
        )

        org.junit.jupiter.api.assertThrows<NumberFormatException> {
            IntentExtraValue.fromOverride("k", "abc", "int")
        }
    }
}
