package com.danielealbano.androidremotecontrolmcp.services.accessibility

import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext

/**
 * Explicit outcome semantics for asynchronous UI event dispatches (handoff item H-10).
 *
 * Every accessibility-driven dispatch result must map onto exactly one of these values;
 * free-text or null outcomes are not permitted. Per the control-plane contract
 * (`unknown_outcome` semantics), cancellations, deadline expiry, and missing callbacks are
 * [UNKNOWN_OUTCOME] — the underlying gesture may still have completed in the real system —
 * never [FAILED].
 *
 * [wireName] is the only string form of an outcome on the wire (tool result metadata/text).
 */
enum class UiEventOutcome(
    val wireName: String,
) {
    /**
     * The dispatch's documented completion condition was observed (contract completion,
     * not a business-effect guarantee).
     */
    COMPLETED("completed"),

    /**
     * A known failure: the dispatch provably never reached (or was rejected upfront by
     * quota validation, or the target provably performed no action). Outcome is certain.
     */
    FAILED("failed"),

    /**
     * The dispatch may or may not have taken effect: deadline expiry, framework-reported
     * cancellation, or a stale tree generation. Never auto-replayed; the caller must
     * observe state before issuing any new request.
     */
    UNKNOWN_OUTCOME("unknown_outcome"),
}

/**
 * Marks a dispatch whose final outcome could not be determined: the operation may still
 * complete later in the real system, so callers (and the server) must never treat it as a
 * failure or auto-replay it.
 *
 * Carries the tree generation the dispatch acted on ([treeGeneration]) and the elapsed
 * dispatch time ([elapsedMs]) so results reference the exact generation they belong to.
 *
 * @property treeGeneration Accessibility tree generation at dispatch time, if known.
 * @property elapsedMs Milliseconds spent on the dispatch before it became unknowable, if known.
 */
class UiEventUnknownOutcomeException(
    message: String,
    val treeGeneration: Long? = null,
    val elapsedMs: Long? = null,
) : RuntimeException(message)

/**
 * Typed result of one UI event dispatch. [outcome] carries the only sanctioned semantics;
 * the optional fields give timing and the tree generation the dispatch acted on.
 */
data class UiEventResult(
    val outcome: UiEventOutcome,
    val treeGeneration: Long? = null,
    val elapsedMs: Long? = null,
    val detail: String? = null,
    val error: Throwable? = null,
)

/**
 * Per-invocation metadata channel for dispatches: the tool wrapper installs an instance in
 * the coroutine context, [ActionExecutorImpl] records the dispatched operation's generation
 * and elapsed time into it, and the tool layer reads it back when building result metadata.
 *
 * One instance exists per tool invocation (tool handlers run in their own coroutine), so
 * concurrent tool calls cannot observe each other's dispatch metadata.
 *
 * @property requestId JSON-RPC request id of the enclosing tool call, if available.
 */
class UiEventDispatchMetadata(
    val requestId: String? = null,
) : AbstractCoroutineContextElement(UiEventDispatchMetadata) {
    /** Tree generation recorded by the executing dispatch, if any. */
    var treeGeneration: Long? = null
        private set

    /** Elapsed dispatch time recorded by the executing dispatch, if any. */
    var dispatchElapsedMs: Long? = null
        private set

    /**
     * Records a dispatch outcome. Later recordings overwrite earlier ones: multi-dispatch
     * invocations (e.g. double tap) report the last dispatch's metadata.
     */
    fun record(result: UiEventResult) {
        treeGeneration = result.treeGeneration
        dispatchElapsedMs = result.elapsedMs
    }

    companion object Key : CoroutineContext.Key<UiEventDispatchMetadata>
}
