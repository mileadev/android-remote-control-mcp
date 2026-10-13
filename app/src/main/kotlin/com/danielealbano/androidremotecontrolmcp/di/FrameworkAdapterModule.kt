package com.danielealbano.androidremotecontrolmcp.di

import com.danielealbano.androidremotecontrolmcp.services.adapters.BuildPlatformVersionProvider
import com.danielealbano.androidremotecontrolmcp.services.adapters.FrameworkAdapter
import com.danielealbano.androidremotecontrolmcp.services.adapters.IntentFrameworkAdapter
import com.danielealbano.androidremotecontrolmcp.services.adapters.PlatformVersionProvider
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * DI bindings for the typed framework adapter layer (handoff item H-11):
 * platform version source, framework adapters, and the gated registry.
 */
@Module
@InstallIn(SingletonComponent::class)
object FrameworkAdapterModule {
    @Provides
    @Singleton
    fun providePlatformVersionProvider(): PlatformVersionProvider = BuildPlatformVersionProvider()

    @Provides
    @Singleton
    fun provideFrameworkAdapters(adapter: IntentFrameworkAdapter): List<FrameworkAdapter> = listOf(adapter)
}
