package com.danielealbano.androidremotecontrolmcp.services.adapters

import android.os.Build
import javax.inject.Inject

/**
 * Source of the current Android API level. Isolated behind an interface so
 * version gates are deterministic under JVM unit tests.
 */
interface PlatformVersionProvider {
    val currentApiLevel: Int
}

/** Reads the API level from [Build.VERSION]. */
class BuildPlatformVersionProvider
    @Inject
    constructor() : PlatformVersionProvider {
        override val currentApiLevel: Int
            get() = Build.VERSION.SDK_INT
    }
