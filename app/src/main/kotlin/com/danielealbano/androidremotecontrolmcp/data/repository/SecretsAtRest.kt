package com.danielealbano.androidremotecontrolmcp.data.repository

import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.data.crypto.SecretCipher
import com.danielealbano.androidremotecontrolmcp.data.crypto.SecretCipherException
import com.danielealbano.androidremotecontrolmcp.data.crypto.isSecretEnvelope
import kotlinx.coroutines.flow.first
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

// Secret-at-rest helpers (H-06), extracted from SettingsRepositoryImpl so the
// repository class stays lean; they are shared by the repository instance and
// its file-private mapping layer, which have no class state in common.

private const val TAG = "MCP:SettingsRepo"
private const val JWT_SECRET_BYTES = 32

/**
 * Failed at-rest migration *launches* recorded on this install; 0 when none. One count per process
 * at most: the application, every settings screen and every settings read retry inside a launch and
 * must not each spend the budget.
 */
internal val SECRET_MIGRATION_FAILURES_KEY = intPreferencesKey("secret_migration_failures")

/**
 * Retry budget of the at-rest migration, counted in failing *launches*. A failure is rethrown while
 * attempts remain, so a transient one still surfaces to the caller (fail loudly); after the budget
 * is spent the migration stops throwing, because a restored backup or a cleared Keystore never heals
 * by trying again — and while it was retried from every caller, every `getServerConfig()` threw,
 * which left the app unable to start at all (audit finding 9).
 */
internal const val MAX_SECRET_MIGRATION_FAILURES = 3

/** Failed at-rest migration attempts recorded on this install; 0 when none. */
internal fun secretMigrationFailures(prefs: Preferences): Int = prefs[SECRET_MIGRATION_FAILURES_KEY] ?: 0

/**
 * Records, without any secret material, that the at-rest migration is
 * abandoned. Repeats are harmless: the caller may report on every read, and
 * [SettingsChangeLogger] coalesces them into one operator-log entry per
 * coalescing window.
 */
internal fun reportSecretMigrationAbandoned(context: SecretPersistenceContext) {
    Log.e(
        TAG,
        "Secret-at-rest migration abandoned after $MAX_SECRET_MIGRATION_FAILURES failed launches: " +
            "the at-rest key is unusable, so stored secrets are refused until they are re-provisioned",
    )
    context.settingsChangeLogger.submit("secret_migration_abandoned", "attempting", "abandoned") { _, _ ->
        "Secret-at-rest migration abandoned: the at-rest key is unusable on this install, " +
            "so stored secrets are refused until the app data is re-provisioned"
    }
}

/**
 * Records, without any secret material, that the stored JWT signing secret
 * cannot be authenticated. The caller still rethrows, so issuance keeps failing
 * loudly; repeated reads repeat the report and [SettingsChangeLogger] coalesces
 * those into one operator-log entry per coalescing window.
 */
internal fun reportUnreadableJwtSigningSecret(
    context: SecretPersistenceContext,
    cause: SecretCipherException,
) {
    Log.e(
        TAG,
        "Stored JWT signing secret cannot be authenticated (${cause.javaClass.simpleName}); " +
            "OAuth issuance fails until the app data is re-provisioned. Regenerating it silently " +
            "would invalidate every already-issued token, so the stored value is left untouched",
    )
    context.settingsChangeLogger.submit("jwt_signing_secret_unreadable", "stored", "unusable") { _, _ ->
        "Stored JWT signing secret is unusable: the at-rest key cannot authenticate it, so OAuth " +
            "issuance fails until the app data is re-provisioned"
    }
}

/**
 * Collaborators shared by the secret-at-rest helpers: the [DataStore] being
 * edited, the coalescing change logger, and the active [SecretCipher].
 */
internal class SecretPersistenceContext(
    val dataStore: DataStore<Preferences>,
    val settingsChangeLogger: SettingsChangeLogger,
    val secretCipher: SecretCipher,
) {
    /**
     * Claimed by the first caller of a launch to reach the at-rest migration. The retry budget
     * counts failing *launches*, not failing calls: a single launch retries from the application,
     * from every settings screen and from every `getServerConfig()` (a per-tool-call read), so
     * counting calls spent the whole budget during a keystore hiccup that healed a second later —
     * and once the budget was spent the migration was abandoned for good. It also keeps an
     * abandoned install from re-attempting the encrypting transform on every read: after
     * abandonment the migration is probed once per launch, which is enough to notice a key that
     * came back.
     *
     * The claim is atomic because those callers really do run concurrently — `Application.onCreate`
     * launches the migration on its own `Dispatchers.IO` scope while a settings screen launches the
     * same work on `viewModelScope`. A plain check-then-set lets two first-movers both record a
     * failure, spending the budget of three launches in one.
     */
    internal val attemptedMigrationInThisProcess = AtomicBoolean(false)
}

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
 * - Once the at-rest migration has recorded a failure, unmigrated plaintext is
 *   refused the same way — but only on a cipher that encrypts at rest. Skipping
 *   a migration that cannot encrypt would otherwise leave the at-rest
 *   protection quietly not applying to the very secrets it is meant to cover,
 *   which is worse than reading nothing.
 * - Values are never written to any log, in plaintext or ciphertext.
 */
internal fun readStoredSecret(
    prefs: Preferences,
    key: Preferences.Key<String>,
    secretCipher: SecretCipher,
): String {
    val stored = prefs[key].orEmpty()
    val envelope = isSecretEnvelope(stored)
    // Only an encrypting cipher can be mid-migration: a foreign counter left behind by another
    // flavor over the same app data must never suppress this flavor's own plaintext secrets.
    val refuseUnmigrated =
        stored.isNotEmpty() && !envelope && secretCipher.encryptsAtRest && secretMigrationFailures(prefs) > 0
    if (refuseUnmigrated) {
        Log.w(
            TAG,
            "Stored secret ${key.name} is not an at-rest envelope and the migration has failed; " +
                "refusing to release it",
        )
    }
    return if (stored.isEmpty() || refuseUnmigrated) {
        ""
    } else if (envelope) {
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
    } else {
        stored
    }
}

/**
 * Runs the at-rest secret migration under a durable retry budget (audit finding 9).
 *
 * [migrate] performs one attempt inside a single DataStore edit, which commits only when the whole
 * attempt succeeds. A [SecretCipherException] from it is recorded and rethrown while the retry
 * budget lasts, so a transient failure still surfaces to the caller; once the budget is spent
 * ([MAX_SECRET_MIGRATION_FAILURES]) the migration is abandoned instead: it is not retried per call
 * and no longer throws, so an unusable at-rest key (restored backup, cleared Keystore, rotated key)
 * cannot make every later settings read throw and leave the app unstartable. [readStoredSecret] then
 * refuses the unmigrated plaintext, so the secrets are never served unprotected, and the abandon is
 * recorded without secret material so it is diagnosable.
 *
 * The budget counts *launches*: one failed attempt is recorded per process, however many callers
 * retry inside it, so a transient outage cannot spend the whole budget in one second. An abandoned
 * install keeps probing once per launch, so a keystore that comes back is picked up (the probe's
 * success clears the counter) without re-running the encrypting transform on every read.
 */
internal suspend fun migrateSecretsWithBoundedRetry(
    dataStore: DataStore<Preferences>,
    context: SecretPersistenceContext,
    migrate: suspend (MutablePreferences) -> Unit,
) {
    if (!context.secretCipher.encryptsAtRest) {
        // This flavor performs no at-rest transform, so it can neither spend nor inherit a budget:
        // a counter recorded by another flavor over the same app data cannot be cleared by it
        // otherwise, and would suppress plaintext secrets that this flavor is documented to hold.
        dataStore.edit { prefs ->
            prefs.remove(SECRET_MIGRATION_FAILURES_KEY)
            migrate(prefs)
        }
        return
    }
    val abandoned =
        secretMigrationFailures(dataStore.data.first()) >= MAX_SECRET_MIGRATION_FAILURES
    val attempted = context.attemptedMigrationInThisProcess
    if (abandoned && attempted.get()) {
        reportSecretMigrationAbandoned(context)
        return
    }
    val alreadyRecordedThisLaunch = attempted.getAndSet(true)
    try {
        dataStore.edit { prefs ->
            migrate(prefs)
            // A completed attempt clears the budget: a transient failure heals here.
            prefs.remove(SECRET_MIGRATION_FAILURES_KEY)
        }
    } catch (e: SecretCipherException) {
        if (abandoned) {
            // Still unusable: stay callable, leave the budget spent, and probe again next launch.
            reportSecretMigrationAbandoned(context)
        } else if (alreadyRecordedThisLaunch) {
            throw e
        } else {
            val recorded =
                dataStore.edit { prefs ->
                    prefs[SECRET_MIGRATION_FAILURES_KEY] = secretMigrationFailures(prefs) + 1
                }
            if (secretMigrationFailures(recorded) >= MAX_SECRET_MIGRATION_FAILURES) {
                reportSecretMigrationAbandoned(context)
            } else {
                throw e
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
