package com.danielealbano.androidremotecontrolmcp.services.accessibility

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@DisplayName("UiEventBatchQuota")
class UiEventBatchQuotaTest {
    private companion object {
        const val STANDARD_MAX_BATCH = 16
        const val HARDENED_MAX_BATCH = 8
        const val DEFAULT_DEADLINE_MS = 5_000L
        const val MAX_DEADLINE_MS = 10_000L
    }

    @Nested
    @DisplayName("factory defaults")
    inner class FactoryDefaults {
        @Test
        @DisplayName("standard() documents standard-build quota")
        fun standardDocumentsDefaults() {
            val quota = UiEventBatchQuota.standard()

            assertEquals(STANDARD_MAX_BATCH, quota.maxBatchSize)
            assertEquals(DEFAULT_DEADLINE_MS, quota.defaultDeadlineMs)
            assertEquals(MAX_DEADLINE_MS, quota.maxDeadlineMs)
        }

        @Test
        @DisplayName("forBuild(false) equals standard quota")
        fun forBuildStandardEqualsStandard() {
            assertEquals(UiEventBatchQuota.standard(), UiEventBatchQuota.forBuild(isLabHardened = false))
        }

        @Test
        @DisplayName("forBuild(true) is stricter on batch size, same deadline bounds")
        fun forBuildHardenedTightensBatchSize() {
            val quota = UiEventBatchQuota.forBuild(isLabHardened = true)

            assertEquals(HARDENED_MAX_BATCH, quota.maxBatchSize)
            assertEquals(DEFAULT_DEADLINE_MS, quota.defaultDeadlineMs)
            assertEquals(MAX_DEADLINE_MS, quota.maxDeadlineMs)
        }
    }

    @Nested
    @DisplayName("validate")
    inner class Validate {
        @Test
        @DisplayName("accepts batch within quota and resolves default deadline")
        fun acceptsWithinQuota() {
            val decision = UiEventBatchQuota.standard().validate(operationCount = 3)

            val accepted = assertInstanceOf(UiEventBatchDecision.Accepted::class.java, decision)
            assertEquals(DEFAULT_DEADLINE_MS, accepted.deadlineMs)
        }

        @Test
        @DisplayName("accepts batch of exactly max size")
        fun acceptsExactlyMax() {
            val decision = UiEventBatchQuota.forBuild(isLabHardened = true).validate(HARDENED_MAX_BATCH)

            assertInstanceOf(UiEventBatchDecision.Accepted::class.java, decision)
        }

        @Test
        @DisplayName("rejects empty batch upfront")
        fun rejectsEmptyBatch() {
            val decision = UiEventBatchQuota.standard().validate(operationCount = 0)

            val rejected = assertInstanceOf(UiEventBatchDecision.Rejected::class.java, decision)
            assertTrue(rejected.reason.contains("empty"))
        }

        @Test
        @DisplayName("rejects batch exceeding quota upfront")
        fun rejectsOversizedBatch() {
            val quota = UiEventBatchQuota.forBuild(isLabHardened = true)

            val decision = quota.validate(HARDENED_MAX_BATCH + 1)

            val rejected = assertInstanceOf(UiEventBatchDecision.Rejected::class.java, decision)
            assertTrue(rejected.reason.contains("exceeds max batch size"))
        }

        @Test
        @DisplayName("accepts requested deadline equal to max deadline")
        fun acceptsDeadlineAtMax() {
            val decision = UiEventBatchQuota.standard().validate(1, requestedDeadlineMs = MAX_DEADLINE_MS)

            val accepted = assertInstanceOf(UiEventBatchDecision.Accepted::class.java, decision)
            assertEquals(MAX_DEADLINE_MS, accepted.deadlineMs)
        }

        @Test
        @DisplayName("rejects requested deadline exceeding max deadline")
        fun rejectsDeadlineAboveMax() {
            val decision =
                UiEventBatchQuota.standard().validate(1, requestedDeadlineMs = MAX_DEADLINE_MS + 1)

            val rejected = assertInstanceOf(UiEventBatchDecision.Rejected::class.java, decision)
            assertTrue(rejected.reason.contains("exceeds max deadline"))
        }

        @Test
        @DisplayName("rejects non-positive deadline")
        fun rejectsNonPositiveDeadline() {
            val zeroDecision = UiEventBatchQuota.standard().validate(1, requestedDeadlineMs = 0L)
            val negativeDecision = UiEventBatchQuota.standard().validate(1, requestedDeadlineMs = -1L)

            assertInstanceOf(UiEventBatchDecision.Rejected::class.java, zeroDecision)
            assertInstanceOf(UiEventBatchDecision.Rejected::class.java, negativeDecision)
        }
    }

    @Nested
    @DisplayName("constructor requirements")
    inner class ConstructorRequirements {
        @Test
        @DisplayName("rejects non-positive max batch size")
        fun rejectsNonPositiveMaxBatchSize() {
            assertThrows<IllegalArgumentException> {
                UiEventBatchQuota(
                    maxBatchSize = 0,
                    defaultDeadlineMs = DEFAULT_DEADLINE_MS,
                    maxDeadlineMs = MAX_DEADLINE_MS,
                )
            }
        }

        @Test
        @DisplayName("rejects non-positive default deadline")
        fun rejectsNonPositiveDefaultDeadline() {
            assertThrows<IllegalArgumentException> {
                UiEventBatchQuota(maxBatchSize = 1, defaultDeadlineMs = 0L, maxDeadlineMs = MAX_DEADLINE_MS)
            }
        }

        @Test
        @DisplayName("rejects max deadline below default deadline")
        fun rejectsMaxBelowDefault() {
            assertThrows<IllegalArgumentException> {
                UiEventBatchQuota(
                    maxBatchSize = 1,
                    defaultDeadlineMs = MAX_DEADLINE_MS,
                    maxDeadlineMs = DEFAULT_DEADLINE_MS,
                )
            }
        }
    }
}
