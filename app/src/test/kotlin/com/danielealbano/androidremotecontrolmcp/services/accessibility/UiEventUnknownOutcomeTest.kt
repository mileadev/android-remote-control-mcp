package com.danielealbano.androidremotecontrolmcp.services.accessibility

import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("UiEventBatchDispatcher unknown-outcome and no-replay semantics")
class UiEventUnknownOutcomeTest {
    private companion object {
        const val TRACKED_GENERATION = 42L
        const val STALE_EXPECTED_GENERATION = 41L
        const val SHORT_DEADLINE_MS = 50L
        const val LONG_DELAY_MS = 10_000L
    }

    private fun trackedGenerationTracker(): AccessibilityTreeGenerationTracker =
        mockk {
            every { current() } returns TRACKED_GENERATION
        }

    @Test
    @DisplayName("deadline expiry yields unknown_outcome and does not retry the dispatch")
    fun deadlineExpiryYieldsUnknownOutcome() =
        runTest {
            val dispatcher = UiEventBatchDispatcher(UiEventBatchQuota.standard(), trackedGenerationTracker())
            var invocations = 0

            val result =
                dispatcher.dispatchSingle(
                    UiEventOperation("gesture:timeout-probe") {
                        invocations++
                        delay(LONG_DELAY_MS)
                        Result.success(Unit)
                    },
                    requestedDeadlineMs = SHORT_DEADLINE_MS,
                )

            assertEquals(UiEventOutcome.UNKNOWN_OUTCOME, result.outcome)
            assertEquals(TRACKED_GENERATION, result.treeGeneration)
            assertTrue(result.detail!!.contains("deadline of ${SHORT_DEADLINE_MS}ms expired"))
            assertEquals(1, invocations)
        }

    @Test
    @DisplayName("framework cancellation is classified as unknown_outcome, not failed")
    fun cancelledGestureClassifiedAsUnknown() =
        runTest {
            val dispatcher = UiEventBatchDispatcher(UiEventBatchQuota.standard(), trackedGenerationTracker())

            val result =
                dispatcher.dispatchSingle(
                    UiEventOperation("gesture:cancelled-probe") {
                        Result.failure(UiEventUnknownOutcomeException("Gesture cancelled: swipe"))
                    },
                )

            assertEquals(UiEventOutcome.UNKNOWN_OUTCOME, result.outcome)
            assertEquals(TRACKED_GENERATION, result.treeGeneration)
            assertTrue(result.detail!!.contains("Gesture cancelled"))
        }

    @Test
    @DisplayName("stale expected generation rejects the dispatch without performing it")
    fun staleGenerationSkipsDispatch() =
        runTest {
            val dispatcher = UiEventBatchDispatcher(UiEventBatchQuota.standard(), trackedGenerationTracker())
            var invocations = 0

            val result =
                dispatcher.dispatchSingle(
                    UiEventOperation(
                        operationId = "node-action:stale-probe",
                        expectedTreeGeneration = STALE_EXPECTED_GENERATION,
                    ) {
                        invocations++
                        Result.success(Unit)
                    },
                )

            assertEquals(UiEventOutcome.UNKNOWN_OUTCOME, result.outcome)
            assertEquals(TRACKED_GENERATION, result.treeGeneration)
            assertTrue(result.detail!!.contains("stale tree generation"))
            assertEquals(0, invocations)
        }

    @Test
    @DisplayName("matching expected generation dispatches normally and records the generation")
    fun matchingGenerationDispatchesNormally() =
        runTest {
            val dispatcher = UiEventBatchDispatcher(UiEventBatchQuota.standard(), trackedGenerationTracker())
            var invocations = 0

            val result =
                dispatcher.dispatchSingle(
                    UiEventOperation(
                        operationId = "node-action:fresh-probe",
                        expectedTreeGeneration = TRACKED_GENERATION,
                    ) {
                        invocations++
                        Result.success(Unit)
                    },
                )

            assertEquals(UiEventOutcome.COMPLETED, result.outcome)
            assertEquals(TRACKED_GENERATION, result.treeGeneration)
            assertEquals(1, invocations)
        }

    @Test
    @DisplayName("known failure stays failed and preserves the original error")
    fun knownFailureStaysFailed() =
        runTest {
            val dispatcher = UiEventBatchDispatcher(UiEventBatchQuota.standard(), trackedGenerationTracker())
            val error = IllegalStateException("Global action 'BACK' failed")

            val result =
                dispatcher.dispatchSingle(
                    UiEventOperation("global-action:BACK") { Result.failure(error) },
                )

            assertEquals(UiEventOutcome.FAILED, result.outcome)
            assertEquals(TRACKED_GENERATION, result.treeGeneration)
            assertEquals(error, result.error)
        }

    @Test
    @DisplayName("batch exceeding quota is rejected upfront with zero invocations (fail-fast)")
    fun oversizedBatchFailsFastBeforeAnyDispatch() =
        runTest {
            val quota = UiEventBatchQuota(maxBatchSize = 2, defaultDeadlineMs = 1_000L, maxDeadlineMs = 2_000L)
            val dispatcher = UiEventBatchDispatcher(quota, trackedGenerationTracker())
            var invocations = 0

            val outcome =
                dispatcher.dispatch(
                    (1..3).map { index ->
                        UiEventOperation("gesture:bulk-$index") {
                            invocations++
                            Result.success(Unit)
                        }
                    },
                )

            val rejected = assertInstanceOf(UiEventBatchOutcome.Rejected::class.java, outcome)
            assertTrue(rejected.reason.contains("exceeds max batch size"))
            assertEquals(0, invocations)
        }

    @Test
    @DisplayName("dispatch above quota never runs any of the submitted operations")
    fun rejectedBatchRunsNoOperation() =
        runTest {
            val quota = UiEventBatchQuota(maxBatchSize = 1, defaultDeadlineMs = 1_000L, maxDeadlineMs = 2_000L)
            val dispatcher = UiEventBatchDispatcher(quota, trackedGenerationTracker())
            var invocations = 0

            val outcome =
                dispatcher.dispatch(
                    listOf(
                        UiEventOperation("gesture:first") {
                            invocations++
                            Result.success(Unit)
                        },
                        UiEventOperation("gesture:second") {
                            invocations++
                            Result.success(Unit)
                        },
                    ),
                )

            assertInstanceOf(UiEventBatchOutcome.Rejected::class.java, outcome)
            assertEquals(0, invocations)
        }

    @Test
    @DisplayName("unknown_outcome is terminal: dispatcher never retries or replays the dispatch")
    fun unknownOutcomeIsNeverReplayed() =
        runTest {
            val dispatcher = UiEventBatchDispatcher(UiEventBatchQuota.standard(), trackedGenerationTracker())
            var unknownInvocations = 0
            var retryInvocations = 0

            val unknownResult =
                dispatcher.dispatchSingle(
                    UiEventOperation("gesture:no-replay-probe") {
                        unknownInvocations++
                        Result.failure(UiEventUnknownOutcomeException("Gesture cancelled: tap"))
                    },
                )

            assertEquals(UiEventOutcome.UNKNOWN_OUTCOME, unknownResult.outcome)

            // A later explicit client request is a NEW dispatch: it runs once on its own,
            // but the earlier unknown-outcome dispatch above is never re-run automatically.
            val retryResult =
                dispatcher.dispatchSingle(
                    UiEventOperation("gesture:explicit-retry") {
                        retryInvocations++
                        Result.success(Unit)
                    },
                )

            assertEquals(UiEventOutcome.COMPLETED, retryResult.outcome)
            assertEquals(1, unknownInvocations)
            assertEquals(1, retryInvocations)
        }

    @Test
    @DisplayName("batch results preserve submission order (explicit causal ordering)")
    fun batchPreservesSubmissionOrder() =
        runTest {
            val dispatcher = UiEventBatchDispatcher(UiEventBatchQuota.standard(), trackedGenerationTracker())

            val outcome =
                dispatcher.dispatch(
                    listOf(
                        UiEventOperation("gesture:one") { Result.success(Unit) },
                        UiEventOperation("gesture:two") { Result.failure(IllegalStateException("second failed")) },
                        UiEventOperation("gesture:three") {
                            Result.failure(UiEventUnknownOutcomeException("Gesture cancelled: three"))
                        },
                    ),
                )

            val results = assertInstanceOf(UiEventBatchOutcome.Executed::class.java, outcome).results
            assertEquals(3, results.size)
            assertEquals(UiEventOutcome.COMPLETED, results[0].outcome)
            assertEquals(UiEventOutcome.FAILED, results[1].outcome)
            assertEquals(UiEventOutcome.UNKNOWN_OUTCOME, results[2].outcome)
        }
}
