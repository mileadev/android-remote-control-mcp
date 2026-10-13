package com.danielealbano.androidremotecontrolmcp.services.adapters

/**
 * Typed representation of an intent extra value.
 *
 * Conversion factories preserve the exact historical semantics of the intent
 * dispatcher: null values are skipped during inference, integral decimals map to
 * [Int32]/[Int64] depending on range, other decimals map to [Float64], and
 * explicit type overrides accept string/int/long/float/double/boolean sources.
 */
sealed interface IntentExtraValue {
    data class Text(
        val value: String,
    ) : IntentExtraValue

    data class Int32(
        val value: Int,
    ) : IntentExtraValue

    data class Int64(
        val value: Long,
    ) : IntentExtraValue

    data class Float32(
        val value: Float,
    ) : IntentExtraValue

    data class Float64(
        val value: Double,
    ) : IntentExtraValue

    data class Bool(
        val value: Boolean,
    ) : IntentExtraValue

    data class StringList(
        val values: List<String>,
    ) : IntentExtraValue

    companion object {
        /**
         * Infers a typed extra from a raw caller value, preserving legacy type
         * inference. Returns null when the value is null and the extra should be
         * skipped entirely. Throws [IllegalArgumentException] for unsupported types.
         */
        fun fromInferred(
            key: String,
            value: Any?,
        ): IntentExtraValue? =
            when (value) {
                null -> {
                    null
                }

                is String -> {
                    Text(value)
                }

                is Boolean -> {
                    Bool(value)
                }

                is List<*> -> {
                    inferList(key, value)
                }

                is Number -> {
                    inferNumeric(value)
                }

                else -> {
                    throw IllegalArgumentException(
                        "Cannot infer extra type for key '$key': unsupported value type",
                    )
                }
            }

        /**
         * Converts a raw caller value under an explicit type override. Throws
         * [IllegalArgumentException] when the override is unsupported, the value is
         * null, or the value cannot be converted to the overridden type.
         */
        fun fromOverride(
            key: String,
            value: Any?,
            typeOverride: String,
        ): IntentExtraValue {
            require(value != null) {
                "Extra '$key' is null but type override '$typeOverride' requires a value"
            }
            return when (typeOverride) {
                "string" -> {
                    Text(value.toString())
                }

                "int" -> {
                    Int32((value as? Number)?.toInt() ?: value.toString().toInt())
                }

                "long" -> {
                    Int64((value as? Number)?.toLong() ?: value.toString().toLong())
                }

                "float" -> {
                    Float32((value as? Number)?.toFloat() ?: value.toString().toFloat())
                }

                "double" -> {
                    Float64((value as? Number)?.toDouble() ?: value.toString().toDouble())
                }

                "boolean" -> {
                    Bool(value as? Boolean ?: value.toString().toBooleanStrict())
                }

                else -> {
                    throw IllegalArgumentException(
                        "Unsupported extras_types value: '$typeOverride'. " +
                            "Supported: string, int, long, float, double, boolean",
                    )
                }
            }
        }

        private fun inferNumeric(value: Number): IntentExtraValue {
            val doubleVal = value.toDouble()
            return if (doubleVal % 1.0 == 0.0) {
                val longVal = value.toLong()
                if (longVal in Int.MIN_VALUE..Int.MAX_VALUE) {
                    Int32(longVal.toInt())
                } else {
                    Int64(longVal)
                }
            } else {
                Float64(doubleVal)
            }
        }

        private fun inferList(
            key: String,
            value: List<*>,
        ): IntentExtraValue =
            if (value.all { it is String }) {
                StringList(value.filterIsInstance<String>())
            } else {
                throw IllegalArgumentException(
                    "Cannot infer extra type for key '$key': unsupported value type",
                )
            }
    }
}
