package com.danielealbano.androidremotecontrolmcp.data.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("Secret cipher envelope format and fail-closed contract")
class KeystoreSecretCipherTest {
    private val cipher = KeystoreSecretCipher()

    @Nested
    @DisplayName("envelope format")
    inner class EnvelopeFormat {
        @Test
        fun `a well-formed envelope is recognized`() {
            val envelope =
                SECRET_ENVELOPE_PREFIX +
                    "dGVzdC1pdi12YWx1ZQ" +
                    SECRET_ENVELOPE_SEPARATOR +
                    "Y2lwaGVydGV4dC1jYXJyaWVy"
            assertTrue(isSecretEnvelope(envelope))
        }

        @Test
        fun `plaintext values are not envelopes`() {
            assertFalse(isSecretEnvelope("plain-secret-value"))
            assertFalse(isSecretEnvelope(""))
            assertFalse(isSecretEnvelope("$SECRET_ENVELOPE_PREFIX v1"))
            assertFalse(isSecretEnvelope("enc.v1."))
            assertFalse(isSecretEnvelope("$SECRET_ENVELOPE_PREFIX onlyonepart"))
            assertFalse(
                isSecretEnvelope("$SECRET_ENVELOPE_PREFIX dGVzdA Y2lwaGVydGV4dA spaces-not-base64url"),
            )
        }
    }

    @Nested
    @DisplayName("fail-closed behavior on JVM (no AndroidKeyStore provider)")
    inner class FailClosedOnJvm {
        @Test
        fun `encrypt throws SecretCipherException when the keystore is unavailable`() {
            val exception =
                assertThrows(SecretCipherException::class.java) {
                    cipher.encrypt("secret-value-1")
                }
            assertFalse(exception.message!!.contains("secret-value-1"))
        }

        @Test
        fun `decrypt throws SecretCipherException on the JVM without an Android keystore`() {
            val envelope =
                SECRET_ENVELOPE_PREFIX +
                    "dGVzdC1pdi12YWx1ZQ" +
                    SECRET_ENVELOPE_SEPARATOR +
                    "Y2lwaGVydGV4dC1jYXJyaWVy"
            val exception =
                assertThrows(SecretCipherException::class.java) {
                    cipher.decrypt(envelope)
                }
            assertFalse(exception.message!!.contains("dGVzdA"))
        }

        @Test
        fun `decrypt throws SecretCipherException for malformed envelopes`() {
            val candidates =
                listOf(
                    "plain-secret-value",
                    "$SECRET_ENVELOPE_PREFIX onlyonepart",
                    "$SECRET_ENVELOPE_PREFIX abc",
                    "$SECRET_ENVELOPE_PREFIX .",
                    "$SECRET_ENVELOPE_PREFIX !!!not-base64url!!! . !!!not-base64url!!!",
                )
            candidates.forEach { candidate ->
                assertThrows(SecretCipherException::class.java) {
                    cipher.decrypt(candidate)
                }
            }
        }
    }

    @Nested
    @DisplayName("FakeSecretCipher contract (locks the seam semantics)")
    inner class FakeCipherContract {
        private val fake = FakeSecretCipher()

        @Test
        fun `round trips plaintext through an authenticated envelope`() {
            val plaintext = "jwt-signing-value-1"
            val envelope = fake.encrypt(plaintext)
            assertTrue(isSecretEnvelope(envelope))
            assertEquals(plaintext, fake.decrypt(envelope))
        }

        @Test
        fun `a tampered envelope fails integrity verification`() {
            val tampered = tamperSecretEnvelope(fake.encrypt("secret-value-1"))
            assertThrows(SecretCipherException::class.java) { fake.decrypt(tampered) }
        }

        @Test
        fun `a body shorter than the authentication tag fails integrity verification`() {
            val truncated = truncateSecretEnvelope(fake.encrypt("secret-value-1"))
            assertThrows(SecretCipherException::class.java) { fake.decrypt(truncated) }
        }

        @Test
        fun `an unavailable key makes encryption and decryption fail closed`() {
            fake.encrypt("secret-value-1")
            fake.makeKeyUnavailable()
            assertThrows(SecretCipherException::class.java) { fake.encrypt("secret-value-2") }
            val envelope =
                SECRET_ENVELOPE_PREFIX + "dGVzdA" + SECRET_ENVELOPE_SEPARATOR + "Y2lwaGVy"
            assertThrows(SecretCipherException::class.java) { fake.decrypt(envelope) }
        }

        @Test
        fun `a rotated key renders older envelopes unusable`() {
            val envelope = fake.encrypt("secret-value-1")
            fake.rotateKey()
            assertThrows(SecretCipherException::class.java) { fake.decrypt(envelope) }
            assertEquals("secret-value-2", fake.decrypt(fake.encrypt("secret-value-2")))
        }

        @Test
        fun `pass-through cipher keeps plaintext semantics`() {
            assertFalse(PlaintextSecretCipher.encryptsAtRest)
            assertEquals("secret-value-1", PlaintextSecretCipher.encrypt("secret-value-1"))
            assertEquals("secret-value-1", PlaintextSecretCipher.decrypt("secret-value-1"))
        }

        @Test
        fun `pass-through cipher refuses an envelope instead of returning its ciphertext`() {
            val envelope = FakeSecretCipher().encrypt("secret-value-1")

            val attempt = assertThrows(SecretCipherException::class.java) { PlaintextSecretCipher.decrypt(envelope) }

            assertFalse(attempt.message.orEmpty().contains(envelope))
            assertFalse(attempt.message.orEmpty().contains("secret-value-1"))
        }
    }
}
