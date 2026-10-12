package com.danielealbano.androidremotecontrolmcp.mcp.tools

import android.util.Log
import com.danielealbano.androidremotecontrolmcp.data.model.ToolPermissionsConfig
import kotlinx.coroutines.CancellationException
import java.io.IOException

/**
 * Dispatch-path enforcement of the tool capability policy.
 *
 * Registration-time gating only hides tools from discovery and cannot react to policy
 * changes while the server runs. A gate evaluated per tool call applies the CURRENT
 * policy (including changes written while the server is running) to already-registered
 * tools, producing a "discovered but denied" state for revoked tools.
 *
 * Hardened builds install an active gate backed by the settings repository; other
 * flavors use [INACTIVE] to keep upstream behavior (registration-time enforcement only).
 *
 * Policy-store failures fail closed: an [IOException] (which covers DataStore
 * corruption) denies the call rather than allowing it.
 */
class ToolPolicyGate(
    private val currentConfig: suspend () -> ToolPermissionsConfig,
) {
    /**
     * True when [toolName] may execute under the current policy snapshot.
     *
     * @throws kotlinx.coroutines.CancellationException if the policy read is cancelled.
     */
    suspend fun allows(toolName: String): Boolean =
        try {
            currentConfig().isToolEnabled(toolName)
        } catch (e: CancellationException) {
            throw e
        } catch (e: IOException) {
            Log.w(TAG, "Tool policy store unreadable; denying tool call '$toolName'", e)
            false
        }

    companion object {
        /**
         * Pass-through gate for flavors without hardened dispatch enforcement: every call
         * that was allowed at registration time remains allowed.
         */
        val INACTIVE = ToolPolicyGate { ToolPermissionsConfig() }

        private const val TAG = "ToolPolicyGate"
    }
}
