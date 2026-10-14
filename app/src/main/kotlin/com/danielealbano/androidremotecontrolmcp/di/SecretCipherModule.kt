package com.danielealbano.androidremotecontrolmcp.di

import com.danielealbano.androidremotecontrolmcp.BuildConfig
import com.danielealbano.androidremotecontrolmcp.data.crypto.KeystoreSecretCipher
import com.danielealbano.androidremotecontrolmcp.data.crypto.PlaintextSecretCipher
import com.danielealbano.androidremotecontrolmcp.data.crypto.SecretCipher
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Provides the at-rest cipher for persisted secrets: Android Keystore
 * AES-GCM on the lab-hardened flavor (fail-closed posture), upstream
 * plaintext behavior (with upstream-compatible semantics) on other flavors.
 */
@Module
@InstallIn(SingletonComponent::class)
object SecretCipherModule {
    @Provides
    @Singleton
    fun provideSecretCipher(): SecretCipher =
        if (BuildConfig.LAB_HARDENED) {
            KeystoreSecretCipher()
        } else {
            PlaintextSecretCipher
        }
}
