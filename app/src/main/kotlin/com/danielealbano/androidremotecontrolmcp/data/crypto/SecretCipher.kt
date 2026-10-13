package com.danielealbano.androidremotecontrolmcp.data.crypto

/**
 * Contract for protecting persisted secrets (bearer tokens, JWT signing
 * secrets, tunnel credentials) at rest.
 *
 * ## Security invariants
 *
 * - [encrypt] always yields a self-describing envelope in the
 *   [SECRET_ENVELOPE_PREFIX] wire format; [decrypt] authenticates it back to
 *   the original plaintext. It never returns a best-effort partial value.
 * - [decrypt] throws [SecretCipherException] when the envelope is malformed,
 *   was tampered with, or was produced under a key that no longer exists.
 *   Callers are expected to fail closed on that exception — never to fall
 *   back to plaintext and never to silently reset the stored value.
 * - Implementations must never write secret material (plaintext, ciphertext,
 *   key material, or envelopes) to logs; integrity failures are signaled by
 *   throwing or being caught out-of-band without echoing the value.
 * - [encryptsAtRest] tells the persistence layer whether secret preferences
 *   hold envelopes (triggering authenticated one-time migration of legacy
 *   plaintext) and does not alter non-secret preferences.
 */
interface SecretCipher {
    /** True when this cipher persists secrets as encrypted envelopes. */
    val encryptsAtRest: Boolean

    /**
     * Encrypts [plaintext] into an authenticated tamper-evident envelope, or
     * throws [SecretCipherException] if the backing key is unavailable.
     */
    fun encrypt(plaintext: String): String

    /**
     * Decrypts and authenticates [envelope] back to the original plaintext,
     * or throws [SecretCipherException] on any integrity or key failure.
     */
    fun decrypt(envelope: String): String
}

/**
 * Raised when a secret envelope cannot be authenticated or decrypted. The
 * message intentionally carries no secret-derived material.
 */
class SecretCipherException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * Envelope wire format: `enc.v1.<base64url(iv)>.<base64url(ciphertext+tag)>`
 * where both fields are unpadded base64url. The version marker keeps
 * migration idempotent (already-encrypted values are detectably different
 * from plaintext) and lets future schemes rotate the format.
 */
const val SECRET_ENVELOPE_PREFIX = "enc.v1."
const val SECRET_ENVELOPE_SEPARATOR = '.'
val SECRET_ENVELOPE_PATTERN = Regex("^enc\\.v1\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$")

/** True when [value] is shaped like a [SecretCipher] envelope. */
fun isSecretEnvelope(value: String): Boolean = SECRET_ENVELOPE_PATTERN.matches(value)

/**
 * Pass-through cipher for flavors and tests where persisted secrets stay
 * plaintext with upstream semantics. Never used by the lab-hardened build.
 */
object PlaintextSecretCipher : SecretCipher {
    override val encryptsAtRest: Boolean = false

    override fun encrypt(plaintext: String): String = plaintext

    override fun decrypt(envelope: String): String = envelope
}
