package com.danielealbano.androidremotecontrolmcp.services.adapters

import android.content.Context
import android.content.Intent
import android.net.Uri
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject

/**
 * Typed adapter over the Android intent framework.
 *
 * The adapter owns all `Context` intent invocations for the intents domain. It
 * declares its supported API level range and action schemas, refuses per-flag
 * features that exceed the device API level with typed rejections, and never
 * inspects runtime state to decide what to call: every platform interaction is a
 * compile-time-checked `Intent` construction followed by a fixed
 * start/send/start call.
 *
 * Intents require no Android permissions, so [requiredPermissions] is empty;
 * permission gating for other (future) adapters is enforced by the registry.
 *
 * Platform exceptions (not found, security, background-start restrictions) are
 * intentionally propagated to the dispatcher, which keeps the historical typed
 * `Result` mapping in one place.
 */
class IntentFrameworkAdapter
    @Inject
    constructor(
        @param:ApplicationContext private val context: Context,
        private val platformVersion: PlatformVersionProvider,
    ) : FrameworkAdapter {
        override val id: String = ID

        override val domain: String = DOMAIN

        override val supportedApiLevels: IntRange = MIN_API_LEVEL..MAX_API_LEVEL

        override val requiredPermissions: List<String> = emptyList()

        override val actionSchemas: List<AdapterActionSpec> =
            listOf(
                AdapterActionSpec(
                    actionId = IntentFrameworkAction.DispatchIntent.ACTION_ID,
                    description = "Build and dispatch an Android intent (activity, broadcast, or service).",
                    inputFields =
                        mapOf(
                            "delivery" to AdapterFieldType.ENUM,
                            "intentAction" to AdapterFieldType.STRING_NULLABLE,
                            "dataUri" to AdapterFieldType.STRING_NULLABLE,
                            "component" to AdapterFieldType.STRING_NULLABLE,
                            "packageName" to AdapterFieldType.STRING_NULLABLE,
                            "extras" to AdapterFieldType.STRING_VALUE_MAP,
                            "flags" to AdapterFieldType.STRING_LIST,
                        ),
                    outputFields = emptyMap(),
                    minApiLevel = MIN_API_LEVEL,
                    enumValues = mapOf("delivery" to listOf("ACTIVITY", "BROADCAST", "SERVICE")),
                ),
                AdapterActionSpec(
                    actionId = IntentFrameworkAction.OpenUri.ACTION_ID,
                    description = "Open a URI through a VIEW intent.",
                    inputFields =
                        mapOf(
                            "uri" to AdapterFieldType.STRING,
                            "packageName" to AdapterFieldType.STRING_NULLABLE,
                            "mimeType" to AdapterFieldType.STRING_NULLABLE,
                        ),
                    outputFields = emptyMap(),
                    minApiLevel = MIN_API_LEVEL,
                ),
            )

        override fun supports(action: AdapterAction): Boolean = action is IntentFrameworkAction

        override suspend fun dispatch(action: AdapterAction): AdapterOutcome {
            val apiLevel = platformVersion.currentApiLevel
            if (apiLevel !in supportedApiLevels) {
                return AdapterOutcome.Rejected(
                    AdapterRejection.UnsupportedApiLevel(id, supportedApiLevels, apiLevel),
                )
            }
            return when (action) {
                is IntentFrameworkAction.DispatchIntent -> {
                    dispatchIntent(action, apiLevel)
                }

                is IntentFrameworkAction.OpenUri -> {
                    dispatchOpenUri(action)
                }

                else -> {
                    AdapterOutcome.Rejected(
                        AdapterRejection.UnknownAction(action.actionId, declaredActionIds()),
                    )
                }
            }
        }

        private fun dispatchIntent(
            action: IntentFrameworkAction.DispatchIntent,
            apiLevel: Int,
        ): AdapterOutcome {
            val unsupportedFlag = action.flags.firstOrNull { it.minApiLevel > apiLevel }
            if (unsupportedFlag != null) {
                return AdapterOutcome.Rejected(
                    AdapterRejection.FeatureRequiresNewerApi(
                        feature = unsupportedFlag.name,
                        minApiLevel = unsupportedFlag.minApiLevel,
                        actualApiLevel = apiLevel,
                    ),
                )
            }
            val intent = buildIntent(action)
            when (action.delivery) {
                IntentFrameworkAction.Delivery.ACTIVITY -> context.startActivity(intent)
                IntentFrameworkAction.Delivery.BROADCAST -> context.sendBroadcast(intent)
                IntentFrameworkAction.Delivery.SERVICE -> context.startService(intent)
            }
            return AdapterOutcome.Completed(detail = "delivery=${action.delivery.name}")
        }

        private fun dispatchOpenUri(action: IntentFrameworkAction.OpenUri): AdapterOutcome {
            val intent =
                if (action.mimeType != null) {
                    Intent(Intent.ACTION_VIEW).apply {
                        setDataAndType(Uri.parse(action.uri), action.mimeType)
                    }
                } else {
                    Intent(Intent.ACTION_VIEW, Uri.parse(action.uri))
                }

            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            action.packageName?.let { intent.setPackage(it) }
            context.startActivity(intent)
            return AdapterOutcome.Completed(detail = "view intent started")
        }

        private fun buildIntent(action: IntentFrameworkAction.DispatchIntent): Intent {
            val intent = Intent()
            action.intentAction?.let { intent.action = it }
            action.dataUri?.let { intent.data = Uri.parse(it) }
            action.component?.let { intent.component = it }
            action.packageName?.let { intent.setPackage(it) }

            val allFlags =
                if (action.delivery == IntentFrameworkAction.Delivery.ACTIVITY &&
                    IntentFlagCatalog.FLAG_ACTIVITY_NEW_TASK !in action.flags
                ) {
                    action.flags + IntentFlagCatalog.FLAG_ACTIVITY_NEW_TASK
                } else {
                    action.flags
                }
            if (allFlags.isNotEmpty()) {
                intent.flags =
                    allFlags.fold(0) { combined, flag -> combined or flag.value }
            }

            action.extras.forEach { (key, extra) -> putTypedExtra(intent, key, extra) }
            return intent
        }

        private fun declaredActionIds(): List<String> =
            listOf(
                IntentFrameworkAction.DispatchIntent.ACTION_ID,
                IntentFrameworkAction.OpenUri.ACTION_ID,
            )

        private fun putTypedExtra(
            intent: Intent,
            key: String,
            extra: IntentExtraValue,
        ) {
            when (extra) {
                is IntentExtraValue.Text -> intent.putExtra(key, extra.value)
                is IntentExtraValue.Int32 -> intent.putExtra(key, extra.value)
                is IntentExtraValue.Int64 -> intent.putExtra(key, extra.value)
                is IntentExtraValue.Float32 -> intent.putExtra(key, extra.value)
                is IntentExtraValue.Float64 -> intent.putExtra(key, extra.value)
                is IntentExtraValue.Bool -> intent.putExtra(key, extra.value)
                is IntentExtraValue.StringList -> intent.putExtra(key, ArrayList(extra.values))
            }
        }

        companion object {
            const val ID = "intent-framework"
            const val DOMAIN = "intents"

            /** Device floor aligned with the app's minSdk. */
            const val MIN_API_LEVEL = 33

            /** Device ceiling aligned with the project's compile SDK. */
            const val MAX_API_LEVEL = 37
        }
    }
