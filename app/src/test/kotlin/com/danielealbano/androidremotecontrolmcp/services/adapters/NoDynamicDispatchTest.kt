package com.danielealbano.androidremotecontrolmcp.services.adapters

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Source-scan guard: the adapter layer (and the intent seam it serves) must not
 * reintroduce dynamic dispatch mechanisms — reflection, shell execution,
 * app_process bootstrap, or binder `service call` bypasses. Deterministic: it
 * scans the repository source tree relative to the current working directory.
 */
@DisplayName("NoDynamicDispatch")
class NoDynamicDispatchTest {
    private val forbiddenTokens =
        listOf(
            "java.lang.reflect",
            "kotlin.reflect",
            "Class.forName",
            "getDeclaredMethod",
            "getDeclaredField",
            "getDeclaredConstructor",
            ".declaredMethods",
            ".declaredFields",
            ".declaredProperties",
            ".declaredMemberProperties",
            ".memberFunctions",
            ".memberProperties",
            "setAccessible",
            "::class.java.fields",
            "::class.java.methods",
            "::class.java.constructors",
            "::class.java.declared",
            "Runtime.getRuntime",
            "Runtime.exec",
            "ProcessBuilder",
            "ClassLoader",
            ".loadClass",
            "DexClassLoader",
            "app_process",
            "service call",
        )

    @Test
    fun `adapter layer contains no dynamic dispatch mechanisms`() {
        val sources = adapterLayerSources()
        assertTrue(sources.isNotEmpty(), "Adapter layer sources were not found; scan location changed?")

        val fileNames = sources.map { it.name }
        assertTrue("IntentFrameworkAdapter.kt" in fileNames, "Scan must cover the intent adapter")
        assertTrue("IntentDispatcherImpl.kt" in fileNames, "Scan must cover the intent dispatcher seam")
        assertTrue("FrameworkAdapterRegistry.kt" in fileNames, "Scan must cover the registry gate")

        val violations =
            sources
                .flatMap { file ->
                    val text = file.readText()
                    forbiddenTokens
                        .filter { token -> text.contains(token) }
                        .map { token -> "${file.name}: forbidden mechanism '$token'" }
                }
        assertTrue(violations.isEmpty(), "Dynamic dispatch tokens found:\n${violations.joinToString("\n")}")
    }

    @Test
    fun `adapter layer contains no legacy reflective flag map`() {
        val sources = adapterLayerSources()
        val dispatcher = sources.single { it.name == "IntentDispatcherImpl.kt" }
        assertTrue(
            !dispatcher.readText().contains("::class.java"),
            "Dispatcher must not fall back to class literal introspection",
        )
        assertTrue(
            !dispatcher.readText().contains("flagMap"),
            "Legacy reflective flag map must remain removed",
        )
    }

    private fun adapterLayerSources(): List<File> {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        repeat(6) {
            val current = dir ?: return@repeat
            val serviceBase = "app/src/main/kotlin/com/danielealbano/androidremotecontrolmcp/services"
            val adapters = File(current, "$serviceBase/adapters")
            val intents = File(current, "$serviceBase/intents")
            if (adapters.isDirectory && intents.isDirectory) {
                return (adapters.listFiles { file -> file.name.endsWith(".kt") }?.toList() ?: emptyList()) +
                    (intents.listFiles { file -> file.name.endsWith(".kt") }?.toList() ?: emptyList())
            }
            dir = current.parentFile
        }
        return emptyList()
    }
}
