package com.danielealbano.androidremotecontrolmcp.data.crypto

// Envelope corruption helpers shared by the at-rest crypto tests. Both keep the
// envelope shape valid (it still matches SECRET_ENVELOPE_PATTERN) and corrupt
// the body after the IV, so authentication is what has to refuse the value.

/**
 * Flips the first ciphertext character. The first base64url character of a
 * group is always fully significant, unlike the last one: the low bits of a
 * trailing character are discarded when the encoding is unpadded, so flipping
 * it can leave the decoded bytes unchanged (`secret-bearer-value-1` is 37
 * ciphertext bytes — a base64 length of 50, where a trailing flip is a no-op).
 */
internal fun tamperSecretEnvelope(envelope: String): String {
    val body = envelope.removePrefix(SECRET_ENVELOPE_PREFIX).split(SECRET_ENVELOPE_SEPARATOR)
    val ciphertext = body[1]
    val replacement = if (ciphertext[0] == 'A') 'B' else 'A'
    return SECRET_ENVELOPE_PREFIX +
        body[0] +
        SECRET_ENVELOPE_SEPARATOR +
        replacement +
        ciphertext.substring(1)
}

/**
 * Replaces the ciphertext with a body shorter than the 16-byte GCM tag, which
 * is how a truncated or partly overwritten preference is read back.
 */
internal fun truncateSecretEnvelope(envelope: String): String {
    val iv = envelope.removePrefix(SECRET_ENVELOPE_PREFIX).split(SECRET_ENVELOPE_SEPARATOR)[0]
    return SECRET_ENVELOPE_PREFIX + iv + SECRET_ENVELOPE_SEPARATOR + BELOW_TAG_LENGTH_BODY
}

/** Base64url of `cipher` — six bytes, ten short of the tag. */
private const val BELOW_TAG_LENGTH_BODY = "Y2lwaGVy"
