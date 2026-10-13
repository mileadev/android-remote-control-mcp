package com.danielealbano.androidremotecontrolmcp.services.accessibility

import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject

/**
 * Monotonic version counter for accessibility tree snapshots (H-10 UI snapshot versions).
 *
 * Every atomic snapshot publication into the node cache bumps the generation; dispatches
 * record the generation they acted on. Generations never decrease: [current] only grows.
 * Generation [INITIAL_GENERATION] (0) means "no snapshot published yet".
 */
interface AccessibilityTreeGenerationTracker {
    /** Current generation: how many snapshots have been published (0 before the first). */
    fun current(): Long

    /** Advances the generation and returns the new value (monotonically increasing). */
    fun bump(): Long
}

/**
 * Thread-safe implementation backed by an [AtomicLong]. Each bump is a single atomic
 * increment; generations are always increasing and cannot be reset.
 */
class TreeGenerationTrackerImpl
    @Inject
    constructor() : AccessibilityTreeGenerationTracker {
        private val generation = AtomicLong(INITIAL_GENERATION)

        override fun current(): Long = generation.get()

        override fun bump(): Long = generation.incrementAndGet()

        companion object {
            private const val INITIAL_GENERATION = 0L
        }
    }
