package com.danielealbano.androidremotecontrolmcp.services.intents

import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.net.Uri
import com.danielealbano.androidremotecontrolmcp.services.adapters.AdapterOutcome
import com.danielealbano.androidremotecontrolmcp.services.adapters.FrameworkAdapterRegistry
import com.danielealbano.androidremotecontrolmcp.services.adapters.IntentExtraValue
import com.danielealbano.androidremotecontrolmcp.services.adapters.IntentFlagCatalog
import com.danielealbano.androidremotecontrolmcp.services.adapters.IntentFrameworkAction
import com.danielealbano.androidremotecontrolmcp.services.adapters.describe
import com.danielealbano.androidremotecontrolmcp.utils.Logger
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject

/**
 * Dispatches intents and opens URIs by delegating to the typed framework adapter
 * layer ([FrameworkAdapterRegistry]). Wire-facing request handling (type
 * validation, component parsing, flag-name resolution, extra conversion) stays
 * here; platform invocation and version/permission gating live in the adapter.
 */
class IntentDispatcherImpl
    @Inject
    constructor(
        @param:ApplicationContext private val context: Context,
        private val frameworkAdapters: FrameworkAdapterRegistry,
    ) : IntentDispatcher {
        override suspend fun sendIntent(request: SendIntentRequest): Result<Unit> {
            if (request.type !in VALID_TYPES) {
                return Result.failure(
                    IllegalArgumentException(
                        "Invalid intent type: '${request.type}'. Must be one of: activity, broadcast, service",
                    ),
                )
            }

            return try {
                val component = request.component?.let { parseComponent(it).getOrThrow() }
                val flags = resolveFlags(request.flags.orEmpty()).getOrThrow()
                val extras = buildExtras(request)
                val action =
                    IntentFrameworkAction.DispatchIntent(
                        delivery = deliveryFor(request.type),
                        intentAction = request.action,
                        dataUri = request.data,
                        component = component,
                        packageName = request.packageName,
                        extras = extras,
                        flags = flags,
                    )
                when (val outcome = frameworkAdapters.dispatch(action)) {
                    is AdapterOutcome.Completed -> {
                        Logger.i(TAG, "Intent dispatched: type=${request.type}, action=${request.action}")
                        Result.success(Unit)
                    }

                    is AdapterOutcome.Failed -> {
                        Logger.w(TAG, "Intent dispatch failed: ${outcome.message}")
                        Result.failure(IllegalArgumentException(outcome.message))
                    }

                    is AdapterOutcome.Rejected -> {
                        Logger.w(TAG, "Intent dispatch rejected: ${outcome.rejection.describe()}")
                        Result.failure(IllegalArgumentException(outcome.rejection.describe()))
                    }
                }
            } catch (e: ActivityNotFoundException) {
                Logger.w(TAG, "No activity found to handle intent", e)
                Result.failure(IllegalArgumentException("No activity found to handle intent"))
            } catch (e: SecurityException) {
                Logger.w(TAG, "Permission denied for intent", e)
                Result.failure(IllegalArgumentException("Permission denied: not allowed to start component"))
            } catch (e: IllegalStateException) {
                Logger.w(TAG, "Illegal state for intent dispatch", e)
                Result.failure(IllegalStateException("Cannot start component: background start restriction"))
            } catch (e: IllegalArgumentException) {
                Logger.w(TAG, "Invalid argument for intent", e)
                Result.failure(e)
            } catch (
                @Suppress("TooGenericExceptionCaught") e: Exception,
            ) {
                Logger.e(TAG, "Unexpected error dispatching intent", e)
                Result.failure(IllegalStateException("Intent dispatch failed unexpectedly"))
            }
        }

        override suspend fun openUri(
            uri: String,
            packageName: String?,
            mimeType: String?,
        ): Result<Unit> =
            try {
                val outcome =
                    frameworkAdapters.dispatch(
                        IntentFrameworkAction.OpenUri(
                            uri = uri,
                            packageName = packageName,
                            mimeType = mimeType,
                        ),
                    )
                when (outcome) {
                    is AdapterOutcome.Completed -> {
                        Logger.i(TAG, "URI opened: ${truncateUri(uri)}")
                        Result.success(Unit)
                    }

                    is AdapterOutcome.Failed -> {
                        Result.failure(IllegalArgumentException(outcome.message))
                    }

                    is AdapterOutcome.Rejected -> {
                        Result.failure(IllegalArgumentException(outcome.rejection.describe()))
                    }
                }
            } catch (e: ActivityNotFoundException) {
                Logger.w(TAG, "No app found to handle URI: ${truncateUri(uri)}", e)
                Result.failure(IllegalArgumentException("No app found to handle URI"))
            } catch (e: SecurityException) {
                Logger.w(TAG, "Permission denied opening URI: ${truncateUri(uri)}", e)
                Result.failure(IllegalArgumentException("Permission denied: not allowed to open URI"))
            } catch (
                @Suppress("TooGenericExceptionCaught") e: Exception,
            ) {
                Logger.e(TAG, "Unexpected error opening URI: ${truncateUri(uri)}", e)
                Result.failure(IllegalStateException("Failed to open URI unexpectedly"))
            }

        private fun deliveryFor(type: String): IntentFrameworkAction.Delivery =
            when (type) {
                TYPE_ACTIVITY -> IntentFrameworkAction.Delivery.ACTIVITY
                TYPE_BROADCAST -> IntentFrameworkAction.Delivery.BROADCAST
                else -> IntentFrameworkAction.Delivery.SERVICE
            }

        private fun buildExtras(request: SendIntentRequest): Map<String, IntentExtraValue> {
            val extras = request.extras.orEmpty()
            if (extras.isEmpty()) {
                return emptyMap()
            }
            val converted = LinkedHashMap<String, IntentExtraValue>(extras.size)
            extras.forEach { (key, value) ->
                try {
                    val typeOverride = request.extrasTypes?.get(key)
                    val typedExtra =
                        if (typeOverride != null) {
                            IntentExtraValue.fromOverride(key, value, typeOverride)
                        } else {
                            IntentExtraValue.fromInferred(key, value) ?: return@forEach
                        }
                    converted[key] = typedExtra
                } catch (
                    @Suppress("TooGenericExceptionCaught") e: Exception,
                ) {
                    throw IllegalArgumentException("Failed to convert extra '$key': ${e.message}", e)
                }
            }
            return converted
        }

        private fun resolveFlags(flagNames: List<String>): Result<List<IntentFlagCatalog>> {
            val resolved = ArrayList<IntentFlagCatalog>(flagNames.size)
            for (name in flagNames) {
                val flag =
                    IntentFlagCatalog.find(name)
                        ?: return Result.failure(IllegalArgumentException("Unknown flag: '$name'"))
                resolved.add(flag)
            }
            return Result.success(resolved)
        }

        private fun parseComponent(component: String): Result<ComponentName> {
            val slashIndex = component.indexOf('/')
            if (slashIndex < 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Invalid component format: '$component'. Expected 'package/class'",
                    ),
                )
            }
            val pkg = component.substring(0, slashIndex)
            val cls = component.substring(slashIndex + 1)
            return if (pkg.isEmpty() || cls.isEmpty()) {
                Result.failure(
                    IllegalArgumentException(
                        "Invalid component format: '$component'. Package and class must not be empty",
                    ),
                )
            } else {
                Result.success(ComponentName(pkg, cls))
            }
        }

        companion object {
            private const val TAG = "MCP:IntentDispatcher"
            private const val TYPE_ACTIVITY = "activity"
            private const val TYPE_BROADCAST = "broadcast"
            private const val TYPE_SERVICE = "service"
            private val VALID_TYPES = setOf(TYPE_ACTIVITY, TYPE_BROADCAST, TYPE_SERVICE)

            private fun truncateUri(uri: String): String =
                try {
                    val parsed = Uri.parse(uri)
                    val scheme = parsed.scheme ?: ""
                    val host = parsed.host ?: ""
                    if (host.isNotEmpty()) "$scheme://$host/..." else "$scheme:..."
                } catch (
                    @Suppress("TooGenericExceptionCaught") e: Exception,
                ) {
                    Logger.d(TAG, "Failed to parse URI for truncation: ${e.message}")
                    "<malformed-uri>"
                }
        }
    }
