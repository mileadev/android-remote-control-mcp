package com.danielealbano.androidremotecontrolmcp.mcp.tools

import com.danielealbano.androidremotecontrolmcp.data.model.ServerLogEntry
import com.danielealbano.androidremotecontrolmcp.data.repository.ServerLogRepository
import com.danielealbano.androidremotecontrolmcp.services.accessibility.UiEventDispatchMetadata
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext

private const val NANOS_PER_MILLI = 1_000_000L
private const val FAILED_MARKER = "failed"
private const val DENIED_MARKER = "denied"

/**
 * Error result for tool calls rejected by the [ToolPolicyGate]. The text names only the
 * tool and the policy: no config contents or store internals are revealed.
 */
private fun policyDeniedResult(toolName: String): CallToolResult =
    CallToolResult(
        content = listOf(TextContent(text = "Tool '$toolName' is denied by the tool capability policy.")),
        isError = true,
    )

/**
 * Wraps a tool handler so every invocation is checked by [toolPolicyGate] at dispatch
 * time first: a denied call returns a policy-denied error result without ever reaching
 * [handler], and is recorded in the server log as a [ServerLogEntry.Type.TOOL_CALL]
 * entry with the constant NON-SENSITIVE [DENIED_MARKER] (duration 0).
 *
 * Allowed calls record a TOOL_CALL server-log entry: un-prefixed tool
 * name + duration, plus the constant NON-SENSITIVE [FAILED_MARKER] on failure (isError result or
 * thrown exception). Parameters and free-form error text are NEVER logged (tool errors can echo
 * device-derived data such as URLs). try/finally keeps the wrapper fully transparent — NO
 * exception is caught (and no linting suppression is needed); a cancelled invocation is not
 * logged (its coroutine is no longer active in the finally block).
 */
internal fun loggedToolHandler(
    serverLog: ServerLogRepository,
    toolName: String,
    toolCallIndicator: ToolCallIndicator = ToolCallIndicator.NONE,
    toolPolicyGate: ToolPolicyGate = ToolPolicyGate.INACTIVE,
    handler: suspend (CallToolRequest) -> CallToolResult,
): suspend (CallToolRequest) -> CallToolResult =
    { request ->
        if (toolPolicyGate.allows(toolName)) {
            val startNs = System.nanoTime()
            var completed: CallToolResult? = null
            runCatching { toolCallIndicator.onToolCallStarted(toolName) }
            try {
                // Install the H-10 dispatch metadata element (no client request id is
                // available on the typed CallToolRequest: it lives on the JSON-RPC
                // envelope, so the element carries generation/elapsed context only).
                val result =
                    withContext(UiEventDispatchMetadata()) {
                        handler(request)
                    }
                completed = result
                result
            } finally {
                runCatching { toolCallIndicator.onToolCallFinished(toolName) }
                val durationMs = (System.nanoTime() - startNs) / NANOS_PER_MILLI
                val result = completed
                when {
                    result != null -> {
                        serverLog.log(
                            type = ServerLogEntry.Type.TOOL_CALL,
                            message = if (result.isError == true) FAILED_MARKER else "",
                            toolName = toolName,
                            durationMs = durationMs,
                        )
                    }

                    coroutineContext.isActive -> {
                        serverLog.log(
                            type = ServerLogEntry.Type.TOOL_CALL,
                            message = FAILED_MARKER,
                            toolName = toolName,
                            durationMs = durationMs,
                        )
                    }
                }
            }
        } else {
            serverLog.log(
                type = ServerLogEntry.Type.TOOL_CALL,
                message = DENIED_MARKER,
                toolName = toolName,
                durationMs = 0L,
            )
            policyDeniedResult(toolName)
        }
    }

/**
 * Registers tools on [server], wrapping every handler with per-call TOOL_CALL logging.
 * A class method is used instead of a `Server` extension so the registration signature stays
 * within detekt's default `LongParameterList` function cap (5): `addTool` below has exactly 5
 * value parameters, and swapping `server` → `registrar` keeps every `registerXxxTools` function
 * at its current parameter count.
 */
class LoggedToolRegistrar(
    private val server: Server,
    private val serverLog: ServerLogRepository,
    private val toolCallIndicator: ToolCallIndicator = ToolCallIndicator.NONE,
    private val toolPolicyGate: ToolPolicyGate = ToolPolicyGate.INACTIVE,
) {
    /** [Server.addTool] with per-call TOOL_CALL logging. [toolName] is the un-prefixed display name. */
    fun addTool(
        toolName: String,
        name: String,
        description: String,
        inputSchema: ToolSchema,
        handler: suspend (CallToolRequest) -> CallToolResult,
    ) {
        val wrapped = loggedToolHandler(serverLog, toolName, toolCallIndicator, toolPolicyGate, handler)
        server.addTool(name = name, description = description, inputSchema = inputSchema) { request ->
            wrapped(request)
        }
    }
}
