package com.danielealbano.androidremotecontrolmcp.startup

import android.util.Log
import com.danielealbano.androidremotecontrolmcp.data.repository.SettingsRepository
import kotlinx.coroutines.CancellationException

private const val TAG = "MCP:AuthMigration"

/**
 * Applies the one-time auth-model migration without letting a failure escape the caller's coroutine
 * (audit finding 9).
 *
 * [SettingsRepository.ensureAuthModelMigrated] is deliberately loud: it rethrows while its retry
 * budget lasts, records the attempt, and refuses to release unmigrated plaintext. What must not
 * happen is that failure reaching the process-wide exception handler from a background coroutine —
 * on a device with an unusable at-rest key that killed `Application.onCreate` (and every screen that
 * triggered the migration) on each launch, so the app never started and nothing said why. The
 * failure is therefore logged here and the durable retry counter keeps it diagnosable; the server
 * start path still runs the migration through [SettingsRepository.getServerConfig] and refuses to
 * serve while the bearer token reads empty. Cancellation still propagates.
 */
suspend fun applyAuthModelMigration(settingsRepository: SettingsRepository) {
    runCatching { settingsRepository.ensureAuthModelMigrated() }
        .onFailure { e ->
            // A cancelled scope must still cancel; everything else is contained here.
            if (e is CancellationException) throw e
            Log.w(
                TAG,
                "One-time auth-model migration was not applied on this launch; stored secrets stay " +
                    "unusable until the app data is re-provisioned",
                e,
            )
        }
}
