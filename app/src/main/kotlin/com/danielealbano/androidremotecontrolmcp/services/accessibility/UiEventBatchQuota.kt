package com.danielealbano.androidremotecontrolmcp.services.accessibility

/**
 * Configurable limits for batched UI event dispatches (H-10 batching/quotas/deadlines).
 *
 * A batch exceeding quota is rejected upfront (fail-fast) before any dispatch is performed.
 *
 * Chosen defaults (standard builds):
 * - [maxBatchSize] = [DEFAULT_MAX_BATCH_SIZE] (16) — bounds how many dispatches may be
 *   enqueued in one batch call.
 * - [defaultDeadlineMs] = [DEFAULT_DEADLINE_MS] (5,000) — per-dispatch deadline applied
 *   when the caller does not request one.
 * - [maxDeadlineMs] = [DEFAULT_MAX_DEADLINE_MS] (10,000) — ceiling for any requested
 *   deadline (matches the gesture dispatch timeout).
 *
 * Lab-hardened builds are stricter: [maxBatchSize] = [HARDENED_MAX_BATCH_SIZE] (8) with the
 * same deadline bounds. All flavors guarantee the same outcome contract; only the quota
 * tightness differs.
 */
data class UiEventBatchQuota(
    val maxBatchSize: Int,
    val defaultDeadlineMs: Long,
    val maxDeadlineMs: Long,
) {
    init {
        require(maxBatchSize > 0) { "maxBatchSize must be positive, got: $maxBatchSize" }
        require(defaultDeadlineMs > 0) { "defaultDeadlineMs must be positive, got: $defaultDeadlineMs" }
        require(maxDeadlineMs >= defaultDeadlineMs) {
            "maxDeadlineMs ($maxDeadlineMs) must be >= defaultDeadlineMs ($defaultDeadlineMs)"
        }
    }

    /**
     * Validates a batch request before any dispatch is attempted.
     *
     * @param operationCount Number of dispatches the caller wants to run in one batch.
     * @param requestedDeadlineMs Caller-requested per-dispatch deadline, or null to use
     *   [defaultDeadlineMs].
     * @return [UiEventBatchDecision.Accepted] with the resolved deadline, or
     *   [UiEventBatchDecision.Rejected] with a fail-fast reason.
     */
    fun validate(
        operationCount: Int,
        requestedDeadlineMs: Long? = null,
    ): UiEventBatchDecision {
        val deadlineMs = requestedDeadlineMs ?: defaultDeadlineMs
        val rejectionReason: String? =
            when {
                operationCount == 0 -> "empty batch: no dispatches requested"
                operationCount > maxBatchSize -> "batch size $operationCount exceeds max batch size $maxBatchSize"
                deadlineMs <= 0 -> "deadline must be positive, got: $deadlineMs"
                deadlineMs > maxDeadlineMs -> "deadline $deadlineMs exceeds max deadline $maxDeadlineMs"
                else -> null
            }
        return if (rejectionReason == null) {
            UiEventBatchDecision.Accepted(deadlineMs)
        } else {
            UiEventBatchDecision.Rejected(rejectionReason)
        }
    }

    companion object {
        const val DEFAULT_MAX_BATCH_SIZE = 16

        /** Per-dispatch deadline applied when a batch does not request one. */
        const val DEFAULT_DEADLINE_MS = 5_000L

        /** Ceiling for any requested per-dispatch deadline (matches GESTURE timeout). */
        const val DEFAULT_MAX_DEADLINE_MS = 10_000L

        /** Lab-hardened builds tighten the batch ceiling. */
        const val HARDENED_MAX_BATCH_SIZE = 8

        /** Quota for standard (non-hardened) builds. */
        fun standard(): UiEventBatchQuota =
            UiEventBatchQuota(
                maxBatchSize = DEFAULT_MAX_BATCH_SIZE,
                defaultDeadlineMs = DEFAULT_DEADLINE_MS,
                maxDeadlineMs = DEFAULT_MAX_DEADLINE_MS,
            )

        /** Quota for the current build flavor: stricter on lab-hardened builds. */
        fun forBuild(isLabHardened: Boolean): UiEventBatchQuota =
            if (isLabHardened) {
                UiEventBatchQuota(
                    maxBatchSize = HARDENED_MAX_BATCH_SIZE,
                    defaultDeadlineMs = DEFAULT_DEADLINE_MS,
                    maxDeadlineMs = DEFAULT_MAX_DEADLINE_MS,
                )
            } else {
                standard()
            }
    }
}

/**
 * Decision produced by [UiEventBatchQuota.validate]: either the accepted per-dispatch
 * deadline or a fail-fast rejection reason.
 */
sealed interface UiEventBatchDecision {
    /** Batch is within quota; [deadlineMs] is the resolved per-dispatch deadline. */
    data class Accepted(
        val deadlineMs: Long,
    ) : UiEventBatchDecision

    /** Batch exceeds quota and must be rejected before any dispatch happens. */
    data class Rejected(
        val reason: String,
    ) : UiEventBatchDecision
}
