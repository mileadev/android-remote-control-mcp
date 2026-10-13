package com.danielealbano.androidremotecontrolmcp.data.crypto

import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * JVM test double mirroring [KeystoreSecretCipher]'s contract: AES-256/GCM with a
 * fresh IV per encryption, `enc.v1.<iv>.<ciphertext+tag>` envelopes, and
 * fail-closed behavior when the key is unavailable.
 *
 * Security invariants exercised through this fake: a ciphertext corrupted after
 * write fails MAC verification ([javax.crypto.AEADBadTagException]) instead of
 * decrypting to garbage, and an invalidated key makes every stored envelope
 * unreadable — never silently plaintext.
 */
class FakeSecretCipher : SecretCipher {
    override val encryptsAtRest: Boolean = true

    private var key = newKey()
    private var keyUnavailable = false

    /** Simulates key invalidation (wiped keystore). Both directions fail closed. */
    fun makeKeyUnavailable() {
        keyUnavailable = true
    }

    fun restoreKey() {
        keyUnavailable = false
    }

    /** Simulates a wiped and re-created keystore: old envelopes become unreadable. */
    fun rotateKey() {
        key = newKey()
    }

    override fun encrypt(plaintext: String): String {
        val aesKey = requireAvailableKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return SECRET_ENVELOPE_PREFIX +
            encodeBase64Url(iv) +
            SECRET_ENVELOPE_SEPARATOR +
            encodeBase64Url(ciphertext)
    }

    override fun decrypt(envelope: String): String {
        val aesKey = requireAvailableKey()
        val parts = envelope.removePrefix(SECRET_ENVELOPE_PREFIX).split(SECRET_ENVELOPE_SEPARATOR)
        if (parts.size != ENVELOPE_PART_COUNT) {
            failAuthentication(null)
        }
        val iv =
            try {
                decodeBase64Url(parts[0])
            } catch (e: IllegalArgumentException) {
                failAuthentication(e)
            }
        val ciphertext =
            try {
                decodeBase64Url(parts[1])
            } catch (e: IllegalArgumentException) {
                failAuthentication(e)
            }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return try {
            cipher.doFinal(ciphertext).toString(Charsets.UTF_8)
        } catch (e: GeneralSecurityException) {
            failAuthentication(e)
        }
    }

    private fun failAuthentication(cause: Throwable?): Nothing =
        throw SecretCipherException("Envelope could not be authenticated with the current secret key", cause)

    private fun requireAvailableKey(): SecretKeySpec {
        if (keyUnavailable) {
            throw SecretCipherException("Secret key is unavailable; refusing to access secrets")
        }
        return key
    }

    private fun newKey(): SecretKeySpec {
        val bytes = ByteArray(KEY_SIZE_BYTES)
        SecureRandom().nextBytes(bytes)
        return SecretKeySpec(bytes, "AES")
    }

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val ENVELOPE_PART_COUNT = 2
        const val KEY_SIZE_BYTES = 32
        const val GCM_TAG_LENGTH_BITS = 128

        fun encodeBase64Url(bytes: ByteArray): String =
            java.util.Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes)

        fun decodeBase64Url(text: String): ByteArray =
            java.util.Base64
                .getUrlDecoder()
                .decode(text)
    }
}
