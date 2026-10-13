package com.danielealbano.androidremotecontrolmcp.data.repository

import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.data.crypto.SecretCipher
import com.danielealbano.androidremotecontrolmcp.data.crypto.SecretCipherException
import com.danielealbano.androidremotecontrolmcp.data.crypto.isSecretEnvelope
import kotlinx.coroutines.flow.first
import java.security.SecureRandom
import java.util.Base64

// Secret-at-rest helpers (H-06), extracted from SettingsRepositoryImpl so the
// repository class stays lean; they are shared by the repository instance and
// its file-private mapping layer, which have no class state in common.

private const val TAG = "MCP:SettingsRepo"
private const val JWT_SECRET_BYTES = 32

/**
 * Collaborators shared by the secret-at-rest helpers: the [DataStore] being
 * edited, the coalescing change logger, and the active [SecretCipher].
 */
internal class SecretPersistenceContext(
    val dataStore: DataStore<Preferences>,
    val settingsChangeLogger: SettingsChangeLogger,
    val secretCipher: SecretCipher,
)

/**
 * Reads a persisted secret honoring the [SecretCipher] at-rest policy.
 *
 * Security invariants:
 * - Absent or empty keys read as the empty string; nothing is synthesized.
 * - An envelope that fails integrity verification (tampered ciphertext or an
 *   invalidated key) is never returned and never ignored silently: the
 *   failure is signaled via [Log.w] (without any secret content) and the
 *   empty string is returned, so downstream authentication fails closed —
 *   e.g. a bearer token becomes "" while `bearer_token_enabled` stays its own
 *   plaintext preference, yielding a 401 instead of access.
 * - Values are never written to any log, in plaintext or ciphertext.
 */
internal fun readStoredSecret(
    prefs: Preferences,
    key: Preferences.Key<String>,
    secretCipher: SecretCipher,
): String {
    val stored = prefs[key] ?: return ""
    return when {
        stored.isEmpty() || !isSecretEnvelope(stored) -> {
            stored
        }

        else -> {
            try {
                secretCipher.decrypt(stored)
            } catch (e: SecretCipherException) {
                Log.w(
                    TAG,
                    "Stored secret ${key.name} failed at-rest integrity verification; " +
                        "refusing to release it (${e.javaClass.simpleName})",
                )
                ""
            }
        }
    }
}

/**
 * Persists a secret preference honoring the [SecretCipher] at-rest policy.
 *
 * Security invariants: on an encrypting cipher, non-empty values are stored
 * as authenticated envelopes inside the caller's DataStore edit; empty values
 * clear the preference; no value is ever logged here.
 */
internal fun persistSecretString(
    prefs: MutablePreferences,
    key: Preferences.Key<String>,
    plaintext: String,
    secretCipher: SecretCipher,
) {
    prefs[key] =
        when {
            plaintext.isEmpty() -> ""
            secretCipher.encryptsAtRest -> secretCipher.encrypt(plaintext)
            else -> plaintext
        }
}

/**
 * Replaces a legacy plaintext secret with an at-rest envelope in its own
 * DataStore edit (used outside the batched migration, e.g. JWT bootstrap).
 * A failing [SecretCipher.encrypt] aborts the whole transaction, leaving the
 * plaintext intact and surfacing the failure to the caller — a migration that
 * cannot authenticate its output never silently resets or downgrades stored
 * data. The returned value is re-decrypted from durable storage so callers
 * see what was actually persisted.
 */
internal suspend fun migrateLegacyPlaintextSecret(
    dataStore: DataStore<Preferences>,
    key: Preferences.Key<String>,
    secretCipher: SecretCipher,
    plaintext: String,
): String {
    val envelope = secretCipher.encrypt(plaintext)
    dataStore.edit { prefs ->
        val current = prefs[key]
        if (current.isNullOrEmpty() || current == plaintext) {
            prefs[key] = envelope
        }
    }
    val persisted = dataStore.data.first()[key]
    return if (persisted != null && isSecretEnvelope(persisted)) secretCipher.decrypt(persisted) else plaintext
}

/**
 * One-at-most migration of plaintext secrets to cipher envelopes, executed
 * inside the caller's DataStore edit.
 *
 * Security invariants:
 * - Atomic: DataStore commits the transform's result only when it completes,
 *   so a keystore failure mid-transaction aborts the entire write and leaves
 *   every preference — plaintext included — exactly as it was; the failure is
 *   rethrown to the caller (fail loudly, never silently reset).
 * - Authenticated: writes are AES-GCM envelopes carrying an AEAD tag, and the
 *   migration only ever replaces values it can distinguish from envelopes
 *   ([isSecretEnvelope]), keeping the migration idempotent.
 * - On hardened builds ([BuildConfig.LAB_HARDENED]) the tunnel feature is
 *   stripped, so previously persisted tunnel secrets are removed in the same
 *   transaction and the drop is signaled via [SettingsChangeLogger] — without
 *   logging any credential value.
 * - On non-hardened builds tunnel secrets migrate to envelopes exactly like
 *   the other at-rest keys, keeping upstream persistence semantics.
 */
internal fun migrateSecretsAtRest(
    prefs: MutablePreferences,
    context: SecretPersistenceContext,
    atRestKeys: List<Preferences.Key<String>>,
    tunnelKeys: List<Preferences.Key<String>>,
) {
    val secretCipher = context.secretCipher
    if (!secretCipher.encryptsAtRest) return
    if (BuildConfig.LAB_HARDENED) {
        var droppedTunnelCredentials = false
        // Every tunnel key must be removed — the check must not short-circuit.
        for (tunnelKey in tunnelKeys) {
            if (tunnelKey in prefs) {
                droppedTunnelCredentials = true
            }
            prefs.remove(tunnelKey)
        }
        if (droppedTunnelCredentials) {
            context.settingsChangeLogger.submit("secret_migration_tunnel_drop", "present", "absent") { _, _ ->
                "Tunnel credentials not persisted: tunnel secrets are not persistable on this build"
            }
        }
    }
    for (key in atRestKeys + tunnelKeys) {
        val stored = prefs[key] ?: continue
        if (stored.isNotEmpty() && !isSecretEnvelope(stored)) {
            prefs[key] = secretCipher.encrypt(stored)
        }
    }
}

/**
 * Persists a scalar tunnel credential on builds that keep the tunnel feature;
 * on hardened builds the credential is refused: any previously persisted value
 * is removed and the drop is signaled via [SettingsChangeLogger] — without
 * logging any credential value.
 */
internal suspend fun persistTunnelCredential(
    context: SecretPersistenceContext,
    key: Preferences.Key<String>,
    coalesceKey: String,
    plaintext: String,
    dropMessage: String,
    changeMessage: String,
) {
    if (BuildConfig.LAB_HARDENED) {
        context.dataStore.edit { prefs -> prefs.remove(key) }
        context.settingsChangeLogger.submit(coalesceKey, "stored", "dropped") { _, _ -> dropMessage }
        return
    }
    context.dataStore.edit { prefs ->
        val old = readStoredSecret(prefs, key, context.secretCipher)
        persistSecretString(prefs, key, plaintext, context.secretCipher)
        context.settingsChangeLogger.submit(coalesceKey, old, plaintext) { _, _ -> changeMessage }
    }
}

/**
 * Persists a scalar secret via the at-rest cipher, logging a coalesced change
 * entry whose render ignores the values (no secret ever reaches the logger or
 * the log file; equality/coalescing still compares plaintexts).
 */
internal suspend fun persistSecretScalar(
    context: SecretPersistenceContext,
    key: Preferences.Key<String>,
    coalesceKey: String,
    plaintext: String,
    message: String,
) {
    context.dataStore.edit { prefs ->
        val old = readStoredSecret(prefs, key, context.secretCipher)
        persistSecretString(prefs, key, plaintext, context.secretCipher)
        context.settingsChangeLogger.submit(coalesceKey, old, plaintext) { _, _ -> message }
    }
}

/** Generates and persists the JWT signing secret if absent, honoring the at-rest cipher. */
internal suspend fun createAndPersistJwtSigningSecret(
    context: SecretPersistenceContext,
    key: Preferences.Key<String>,
): String {
    context.dataStore.edit { prefs ->
        if (prefs[key].isNullOrEmpty()) {
            val raw = ByteArray(JWT_SECRET_BYTES).also { SecureRandom().nextBytes(it) }
            persistSecretString(
                prefs,
                key,
                Base64
                    .getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(raw),
                context.secretCipher,
            )
        }
    }
    // read-after-edit: key is guaranteed present, so !! is always safe
    val stored = context.dataStore.data.first()[key]!!
    return if (isSecretEnvelope(stored)) {
        context.secretCipher.decrypt(stored)
    } else {
        stored
    }
}
