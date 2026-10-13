package com.danielealbano.androidremotecontrolmcp.services.adapters

import android.content.ComponentName

/**
 * Typed actions of the intent framework adapter. Concrete action types are the
 * discovery mechanism — no stringly-typed operation lookup.
 */
sealed interface IntentFrameworkAction : AdapterAction {
    /** How the intent is delivered to the platform. */
    enum class Delivery { ACTIVITY, BROADCAST, SERVICE }

    /**
     * Builds and dispatches an intent on the device.
     */
    data class DispatchIntent(
        val delivery: Delivery,
        val intentAction: String?,
        val dataUri: String?,
        val component: ComponentName?,
        val packageName: String?,
        val extras: Map<String, IntentExtraValue>,
        val flags: List<IntentFlagCatalog>,
    ) : IntentFrameworkAction {
        override val actionId: String = ACTION_ID

        companion object {
            const val ACTION_ID = "intents.dispatch_intent"
        }
    }

    /**
     * Opens a URI through a VIEW intent.
     */
    data class OpenUri(
        val uri: String,
        val packageName: String?,
        val mimeType: String?,
    ) : IntentFrameworkAction {
        override val actionId: String = ACTION_ID

        companion object {
            const val ACTION_ID = "intents.open_uri"
        }
    }
}
