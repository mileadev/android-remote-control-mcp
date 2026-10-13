package com.danielealbano.androidremotecontrolmcp.services.adapters

import android.content.Context
import android.content.pm.PackageManager
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Gated entry point to the typed framework adapters.
 *
 * Discovery is declarative: the registry enumerates injected adapters and matches
 * actions by concrete type. Every dispatch passes through three fail-closed
 * gates, in order:
 * 1. platform version - the adapter's supported API level range must contain the
 *    current device API level, and each action's [AdapterActionSpec.minApiLevel]
 *    must not exceed it,
 * 2. permissions - the union of adapter-level and action-level required Android
 *    permissions must be granted,
 * 3. dispatch - the adapter's own typed dispatch performs any finer-grained
 *    gating (e.g. per-feature version checks).
 *
 * The gates are unconditional on every build variant: an action that fails a gate
 * is refused with a typed [AdapterOutcome.Rejected] both on hardened and on
 * consumer builds. This is deliberately stronger than failing closed only on
 * hardened builds — refusing a request early is strictly safer than performing it
 * and keeps gms/foss/labHardened behavior identical.
 */
@Singleton
class FrameworkAdapterRegistry
    @Inject
    constructor(
        private val adapters: List<@JvmSuppressWildcards FrameworkAdapter>,
        private val platformVersion: PlatformVersionProvider,
        @param:ApplicationContext private val context: Context,
    ) {
        suspend fun dispatch(action: AdapterAction): AdapterOutcome {
            val apiLevel = platformVersion.currentApiLevel
            val adapter = adapters.firstOrNull { it.supports(action) }
            return when {
                adapter == null -> AdapterOutcome.Rejected(unknownActionRejection(action))
                else -> dispatchGated(adapter, action, apiLevel)
            }
        }

        private suspend fun dispatchGated(
            adapter: FrameworkAdapter,
            action: AdapterAction,
            apiLevel: Int,
        ): AdapterOutcome {
            val spec = adapter.actionSchemas.firstOrNull { it.actionId == action.actionId }
            return when {
                apiLevel !in adapter.supportedApiLevels -> {
                    AdapterOutcome.Rejected(
                        AdapterRejection.UnsupportedApiLevel(adapter.id, adapter.supportedApiLevels, apiLevel),
                    )
                }

                spec == null -> {
                    AdapterOutcome.Rejected(unknownActionRejection(action))
                }

                apiLevel < spec.minApiLevel -> {
                    AdapterOutcome.Rejected(
                        AdapterRejection.ActionRequiresNewerApi(action.actionId, spec.minApiLevel, apiLevel),
                    )
                }

                else -> {
                    dispatchPermissionGated(adapter, spec, action)
                }
            }
        }

        private suspend fun dispatchPermissionGated(
            adapter: FrameworkAdapter,
            spec: AdapterActionSpec,
            action: AdapterAction,
        ): AdapterOutcome {
            val required = adapter.requiredPermissions + spec.requiredPermissions
            val missing =
                required.filterNot {
                    context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
                }
            return when {
                missing.isNotEmpty() -> AdapterOutcome.Rejected(AdapterRejection.MissingPermissions(missing))
                else -> adapter.dispatch(action)
            }
        }

        private fun unknownActionRejection(action: AdapterAction): AdapterRejection =
            AdapterRejection.UnknownAction(
                actionId = action.actionId,
                supportedActionIds = adapters.flatMap { it.actionSchemas }.map { it.actionId },
            )
    }
