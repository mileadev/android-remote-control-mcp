package com.danielealbano.androidremotecontrolmcp.services.accessibility

import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.TimeSource

/**
 * One dispatch inside a batch: [operationId] identifies it for traces and diagnostics,
 * [expectedTreeGeneration] (optional) is the tree generation the caller acted on when the
 * dispatch was planned, and [action] is the dispatch itself.
 *
 * [action] is invoked AT MOST ONCE: the dispatcher never retries or replays a dispatch —
 * in particular, an [UiEventOutcome.UNKNOWN_OUTCOME] result is terminal for this operation
 * and only a new explicit caller request can dispatch again.
 */
class UiEventOperation(
    val operationId: String,
    val expectedTreeGeneration: Long? = null,
    val action: suspend () -> Result<Unit>,
)

/**
 * Outcome of a batch dispatch request.
 */
sealed interface UiEventBatchOutcome {
    /**
     * The batch exceeded quota and was rejected upfront (fail-fast): no dispatch ran.
     */
    data class Rejected(
        val reason: String,
    ) : UiEventBatchOutcome

    /**
     * The batch ran: [results] has exactly one entry per operation, in the same order the
     * operations were submitted (explicit causal ordering).
     */
    data class Executed(
        val results: List<UiEventResult>,
    ) : UiEventBatchOutcome
}

/**
 * Dispatches UI events in batches with fail-fast quota enforcement, per-dispatch
 * deadlines, tree-generation recording and staleness checks, and strictly no replay
 * (handoff item H-10, control-plane contract).
 *
 * Semantics:
 * - Batches are validated against [quota] upfront. A rejected batch performs no dispatch.
 * - Operations run sequentially in submission order: result n observes the effects
 *   (if any) of operations 1..n-1 — explicit causal ordering.
 * - Each dispatch gets [withTimeoutOrNull] bounded by the resolved per-dispatch deadline;
 *   deadline expiry yields [UiEventOutcome.UNKNOWN_OUTCOME] because the underlying system
 *   operation may still complete later.
 * - Every result records the tree generation ([AccessibilityTreeGenerationTracker.current])
 *   the dispatch acted on. An operation whose [UiEventOperation.expectedTreeGeneration]
 *   differs from the current generation is reported as [UiEventOutcome.UNKNOWN_OUTCOME]
 *   without dispatching (the tree moved on; no guessing).
 * - No retry, no replay: each action is invoked at most once per dispatch.
 *
 * Cancellation of the enclosing coroutine propagates untouched (structured concurrency).
 */
class UiEventBatchDispatcher(
    private val quota: UiEventBatchQuota,
    private val generationTracker: AccessibilityTreeGenerationTracker,
    private val timeSource: TimeSource.Monotonic = TimeSource.Monotonic,
) {
    /**
     * Runs [operations] sequentially in submission order, or rejects the batch upfront.
     *
     * @param requestedDeadlineMs Per-dispatch deadline, or null to use the quota default.
     */
    suspend fun dispatch(
        operations: List<UiEventOperation>,
        requestedDeadlineMs: Long? = null,
    ): UiEventBatchOutcome {
        val decision = quota.validate(operations.size, requestedDeadlineMs)
        val deadlineMs =
            when (decision) {
                is UiEventBatchDecision.Rejected -> return UiEventBatchOutcome.Rejected(decision.reason)
                is UiEventBatchDecision.Accepted -> decision.deadlineMs
            }
        val results = operations.map { operation -> executeOperation(operation, deadlineMs) }
        return UiEventBatchOutcome.Executed(results)
    }

    /**
     * Convenience single-dispatch entry point: the legacy fast-path (one operation per
     * tool call) run through the same bounded, generation-aware, no-replay semantics.
     */
    suspend fun dispatchSingle(
        operation: UiEventOperation,
        requestedDeadlineMs: Long? = null,
    ): UiEventResult =
        when (val outcome = dispatch(listOf(operation), requestedDeadlineMs)) {
            is UiEventBatchOutcome.Rejected -> {
                UiEventResult(
                    outcome = UiEventOutcome.FAILED,
                    detail = outcome.reason,
                    error = IllegalArgumentException(outcome.reason),
                )
            }

            is UiEventBatchOutcome.Executed -> {
                outcome.results.single()
            }
        }

    private suspend fun executeOperation(
        operation: UiEventOperation,
        deadlineMs: Long,
    ): UiEventResult {
        val generationAtDispatch = generationTracker.current()
        operation.expectedTreeGeneration?.let { expected ->
            if (expected != generationAtDispatch) {
                return UiEventResult(
                    outcome = UiEventOutcome.UNKNOWN_OUTCOME,
                    treeGeneration = generationAtDispatch,
                    detail =
                        "stale tree generation: expected $expected, current $generationAtDispatch; " +
                            "dispatch '${operation.operationId}' was not performed",
                )
            }
        }
        val startMark = timeSource.markNow()
        val result = withTimeoutOrNull(deadlineMs) { operation.action() }
        val elapsedMs = startMark.elapsedNow().inWholeMilliseconds
        return when {
            result == null -> {
                UiEventResult(
                    outcome = UiEventOutcome.UNKNOWN_OUTCOME,
                    treeGeneration = generationAtDispatch,
                    elapsedMs = elapsedMs,
                    detail =
                        "deadline of ${deadlineMs}ms expired while dispatching " +
                            "'${operation.operationId}'; final outcome unknown",
                )
            }

            result.isSuccess -> {
                UiEventResult(
                    outcome = UiEventOutcome.COMPLETED,
                    treeGeneration = generationAtDispatch,
                    elapsedMs = elapsedMs,
                )
            }

            else -> {
                classifyFailure(result, generationAtDispatch, elapsedMs)
            }
        }
    }

    private fun classifyFailure(
        result: Result<Unit>,
        generationAtDispatch: Long,
        elapsedMs: Long,
    ): UiEventResult {
        val exception =
            result.exceptionOrNull()
                ?: error("Result<Unit> failure without exception")
        return when (exception) {
            is UiEventUnknownOutcomeException -> {
                UiEventResult(
                    outcome = UiEventOutcome.UNKNOWN_OUTCOME,
                    treeGeneration = exception.treeGeneration ?: generationAtDispatch,
                    elapsedMs = exception.elapsedMs ?: elapsedMs,
                    detail = exception.message,
                    error = exception,
                )
            }

            else -> {
                UiEventResult(
                    outcome = UiEventOutcome.FAILED,
                    treeGeneration = generationAtDispatch,
                    elapsedMs = elapsedMs,
                    detail = exception.message,
                    error = exception,
                )
            }
        }
    }
}
