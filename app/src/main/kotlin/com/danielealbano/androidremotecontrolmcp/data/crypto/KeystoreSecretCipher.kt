package com.danielealbano.androidremotecontrolmcp.data.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore-backed AES-GCM implementation of [SecretCipher].
 *
 * ## Security invariants
 *
 * - The AES-256 key is generated inside the Android Keystore
 *   ([ANDROID_PROVIDER]) with purpose ENCRYPT|DECRYPT, GCM block mode, and
 *   randomized encryption required, so every envelope uses a fresh IV and the
 *   key material never leaves secure hardware.
 * - Every envelope carries a GCM authentication tag; [decrypt] verifies it
 *   and throws [SecretCipherException] on tampering, corruption, or a
 *   invalidated/missing keystore entry (fail closed — no plaintext fallback).
 * - Failure messages contain no secret material; the only logging is a
 *   tag-only [Log.i] breadcrumb on key generation.
 */
class KeystoreSecretCipher : SecretCipher {
    override val encryptsAtRest: Boolean = true

    private val lock = Any()

    override fun encrypt(plaintext: String): String =
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, obtainKey())
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext.encodeToByteArray())
            SECRET_ENVELOPE_PREFIX + encode(iv) + SECRET_ENVELOPE_SEPARATOR + encode(ciphertext)
        } catch (e: GeneralSecurityException) {
            throw SecretCipherException("Secret encryption failed: keystore key unavailable", e)
        } catch (e: ProviderException) {
            // Android's keystore provider reports a bad key state (and failing
            // loads) as a runtime ProviderException; never let it escape, so
            // callers see the documented failure either way.
            throw SecretCipherException("Secret encryption failed: keystore key unavailable", e)
        } catch (e: IOException) {
            throw SecretCipherException("Secret encryption failed: keystore key unavailable", e)
        }

    override fun decrypt(envelope: String): String {
        if (!isSecretEnvelope(envelope)) {
            fail("Stored value is not an encrypted secret envelope", null)
        }
        val parts = envelope.removePrefix(SECRET_ENVELOPE_PREFIX).split(SECRET_ENVELOPE_SEPARATOR)
        if (parts.size != ENVELOPE_PART_COUNT) {
            fail("Stored secret envelope could not be parsed", null)
        }
        return try {
            val iv = decode(parts[0])
            val ciphertext = decode(parts[1])
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, obtainKey(), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        } catch (e: GeneralSecurityException) {
            fail("Stored secret failed integrity verification", e)
        } catch (e: ProviderException) {
            // Provider-level failures are runtime exceptions, not
            // GeneralSecurityException: JDK 17's SunJCE reports a body shorter
            // than the GCM tag this way, and AndroidKeyStore's own SPIs report
            // key and StrongBox failures this way.
            fail("Stored secret failed integrity verification", e)
        } catch (e: IOException) {
            fail("Stored secret keystore is unavailable", e)
        } catch (e: IllegalArgumentException) {
            fail("Stored secret envelope could not be parsed", e)
        }
    }

    private fun fail(
        message: String,
        cause: Throwable?,
    ): Nothing = throw SecretCipherException(message, cause)

    /**
     * Returns the keystore AES key, generating it inside the keystore on
     * first use. Synchronized so concurrent callers never race two
     * generations for the same alias.
     */
    private fun obtainKey(): SecretKey =
        synchronized(lock) {
            val keyStore = KeyStore.getInstance(ANDROID_PROVIDER).apply { load(null) }
            (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)
                ?: generateKey()
        }

    private fun generateKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_PROVIDER)
        generator.init(
            KeyGenParameterSpec
                .Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE_BITS)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        val key = generator.generateKey()
        Log.i(TAG, "Generated keystore settings-secrets key")
        return key
    }

    private companion object {
        const val TAG = "MCP:SecretCipher"
        const val ANDROID_PROVIDER = "AndroidKeyStore"
        const val KEY_ALIAS = "mcp_settings_secrets_v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val KEY_SIZE_BITS = 256
        const val ENVELOPE_PART_COUNT = 2
        const val GCM_TAG_LENGTH_BITS = 128

        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun decode(text: String): ByteArray = Base64.getUrlDecoder().decode(text)
    }
}
