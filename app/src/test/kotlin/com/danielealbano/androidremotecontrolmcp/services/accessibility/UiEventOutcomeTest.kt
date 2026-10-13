package com.danielealbano.androidremotecontrolmcp.services.accessibility

import com.danielealbano.androidremotecontrolmcp.mcp.McpToolException
import com.danielealbano.androidremotecontrolmcp.mcp.tools.McpToolUtils
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.coroutines.coroutineContext

@DisplayName("UiEventOutcome")
class UiEventOutcomeTest {
    private companion object {
        const val REQUEST_ID = "req-42"
        const val TREE_GENERATION = 7L
        const val ELAPSED_MS = 123L
    }

    /** Installs the dispatch metadata element and records one dispatch into it. */
    private suspend fun <T> withRecordedMetadata(block: suspend () -> T): T =
        withContext(UiEventDispatchMetadata(REQUEST_ID)) {
            coroutineContext[UiEventDispatchMetadata]?.record(
                UiEventResult(
                    outcome = UiEventOutcome.COMPLETED,
                    treeGeneration = TREE_GENERATION,
                    elapsedMs = ELAPSED_MS,
                ),
            )
            block()
        }

    @Test
    @DisplayName("outcome enum exposes the three contract wire names")
    fun outcomeEnumExposesWireNames() {
        assertEquals("completed", UiEventOutcome.COMPLETED.wireName)
        assertEquals("failed", UiEventOutcome.FAILED.wireName)
        assertEquals("unknown_outcome", UiEventOutcome.UNKNOWN_OUTCOME.wireName)
    }

    @Test
    @DisplayName("unknown-outcome exception carries generation and elapsed fields")
    fun unknownOutcomeExceptionCarriesFields() {
        val exception =
            UiEventUnknownOutcomeException(
                "Gesture cancelled: swipe",
                treeGeneration = TREE_GENERATION,
                elapsedMs = ELAPSED_MS,
            )

        assertEquals("Gesture cancelled: swipe", exception.message)
        assertEquals(TREE_GENERATION, exception.treeGeneration)
        assertEquals(ELAPSED_MS, exception.elapsedMs)
    }

    @Test
    @DisplayName("UiEventResult defaults are null field values")
    fun resultDefaultsAreNull() {
        val result = UiEventResult(UiEventOutcome.COMPLETED)

        assertEquals(UiEventOutcome.COMPLETED, result.outcome)
        assertNull(result.treeGeneration)
        assertNull(result.elapsedMs)
        assertNull(result.detail)
        assertNull(result.error)
    }

    @Test
    @DisplayName("dispatch metadata records generations and elapsed time for the tool result")
    fun metadataRecordIsVisibleWithinElement() {
        val metadata = UiEventDispatchMetadata(REQUEST_ID)

        metadata.record(
            UiEventResult(
                outcome = UiEventOutcome.FAILED,
                treeGeneration = 3L,
                elapsedMs = 10L,
            ),
        )
        metadata.record(
            UiEventResult(
                outcome = UiEventOutcome.COMPLETED,
                treeGeneration = TREE_GENERATION,
                elapsedMs = ELAPSED_MS,
            ),
        )

        assertEquals(TREE_GENERATION, metadata.treeGeneration)
        assertEquals(ELAPSED_MS, metadata.dispatchElapsedMs)
        assertEquals(REQUEST_ID, metadata.requestId)
    }

    @Test
    @DisplayName("successful result maps to completed outcome text and meta")
    fun successMapsToCompletedOutcome() =
        runTest {
            val result = withRecordedMetadata { McpToolUtils.handleActionResult(Result.success(Unit), "Tap executed") }

            val text = (result.content[0] as TextContent).text
            assertTrue(text.startsWith("Tap executed"))
            assertTrue(text.contains("outcome=completed"))
            assertTrue(text.contains("tree_generation=$TREE_GENERATION"))
            assertTrue(text.contains("elapsed_ms=$ELAPSED_MS"))

            val meta = requireNotNull(result.meta) { "expected outcome metadata" }
            assertEquals("completed", meta["outcome"]?.jsonPrimitive?.content)
            assertEquals(TREE_GENERATION.toString(), meta["tree_generation"]?.jsonPrimitive?.content)
            assertEquals(ELAPSED_MS.toString(), meta["elapsed_ms"]?.jsonPrimitive?.content)
            assertEquals(REQUEST_ID, meta["request_id"]?.jsonPrimitive?.content)
            assertTrue(result.isError != true)
        }

    @Test
    @DisplayName("unknown outcome is returned as a normal result, never an error, and never failed")
    fun unknownOutcomeReturnedAsNormalResult() =
        runTest {
            val unknown =
                UiEventUnknownOutcomeException(
                    "Gesture cancelled: swipe",
                    treeGeneration = TREE_GENERATION,
                    elapsedMs = ELAPSED_MS,
                )

            val result =
                withRecordedMetadata {
                    McpToolUtils.handleActionResult(Result.failure(unknown), "Swipe executed")
                }

            val text = (result.content[0] as TextContent).text
            assertTrue(text.contains("Gesture cancelled: swipe"))
            assertTrue(text.contains("outcome=unknown_outcome"))
            val meta = requireNotNull(result.meta) { "expected outcome metadata" }
            assertEquals("unknown_outcome", meta["outcome"]?.jsonPrimitive?.content)
            assertEquals(TREE_GENERATION.toString(), meta["tree_generation"]?.jsonPrimitive?.content)
            assertTrue(result.isError != true)
        }

    @Test
    @DisplayName("generic failure throws ActionFailed with failed outcome token and preserved cause")
    fun genericFailureThrowsActionFailedWithOutcomeToken() {
        val cause = RuntimeException("Something broke")

        val exception =
            assertThrows<McpToolException.ActionFailed> {
                runTest {
                    withRecordedMetadata { McpToolUtils.handleActionResult(Result.failure(cause), "Tap executed") }
                }
            }

        assertTrue(exception.message!!.contains("Something broke"))
        assertTrue(exception.message!!.contains("outcome=failed"))
        assertTrue(exception.message!!.contains("tree_generation=$TREE_GENERATION"))
        // Stack-trace recovery across the dispatch metadata withContext nests the original as a
        // deeper cause link; the failure's original cause must stay reachable from the rethrow.
        val causeChain: Sequence<Throwable> = generateSequence<Throwable>(exception) { it.cause }
        assertTrue(causeChain.contains(cause))
    }

    @Test
    @DisplayName("result without dispatch metadata still carries explicit outcome token")
    fun withoutMetadataStillCarriesOutcomeToken() =
        runTest {
            val result = McpToolUtils.handleActionResult(Result.success(Unit), "Tap executed")

            val text = (result.content[0] as TextContent).text
            assertTrue(text.contains("[outcome=completed]"))
            assertFalse(text.contains("tree_generation"))
            assertNull(result.meta?.get("tree_generation"))
        }
}
