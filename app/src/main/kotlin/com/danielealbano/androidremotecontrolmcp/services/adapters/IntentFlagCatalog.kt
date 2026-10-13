package com.danielealbano.androidremotecontrolmcp.services.adapters

import android.content.Intent

/**
 * Typed catalog of intent flags.
 *
 * Every entry references its [android.content.Intent] constant directly, so flag
 * names and values are compile-time-checked instead of resolved through runtime
 * introspection of `Intent` fields.
 *
 * [minApiLevel] records the platform API level that introduced each public flag;
 * the intent adapter refuses flags whose level exceeds the device API level with
 * a typed rejection instead of silently sending an unsupported value.
 *
 * The catalog intentionally covers only the flags that are visible to this
 * project's compile SDK. Device-only or hidden flags are no longer resolvable —
 * callers requesting them fail with the typed "Unknown flag" error rather than
 * receiving a value obtained at runtime.
 */
enum class IntentFlagCatalog(
    val value: Int,
    val minApiLevel: Int,
) {
    FLAG_ACTIVITY_BROUGHT_TO_FRONT(value = Intent.FLAG_ACTIVITY_BROUGHT_TO_FRONT, minApiLevel = 1),
    FLAG_ACTIVITY_CLEAR_TASK(value = Intent.FLAG_ACTIVITY_CLEAR_TASK, minApiLevel = 11),
    FLAG_ACTIVITY_CLEAR_TOP(value = Intent.FLAG_ACTIVITY_CLEAR_TOP, minApiLevel = 1),
    FLAG_ACTIVITY_CLEAR_WHEN_TASK_RESET(value = Intent.FLAG_ACTIVITY_CLEAR_WHEN_TASK_RESET, minApiLevel = 1),
    FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS(value = Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS, minApiLevel = 1),
    FLAG_ACTIVITY_FORWARD_RESULT(value = Intent.FLAG_ACTIVITY_FORWARD_RESULT, minApiLevel = 16),
    FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY(value = Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY, minApiLevel = 1),
    FLAG_ACTIVITY_LAUNCH_ADJACENT(value = Intent.FLAG_ACTIVITY_LAUNCH_ADJACENT, minApiLevel = 21),
    FLAG_ACTIVITY_MATCH_EXTERNAL(value = Intent.FLAG_ACTIVITY_MATCH_EXTERNAL, minApiLevel = 29),
    FLAG_ACTIVITY_MULTIPLE_TASK(value = Intent.FLAG_ACTIVITY_MULTIPLE_TASK, minApiLevel = 21),
    FLAG_ACTIVITY_NEW_DOCUMENT(value = Intent.FLAG_ACTIVITY_NEW_DOCUMENT, minApiLevel = 21),
    FLAG_ACTIVITY_NEW_TASK(value = Intent.FLAG_ACTIVITY_NEW_TASK, minApiLevel = 1),
    FLAG_ACTIVITY_NO_ANIMATION(value = Intent.FLAG_ACTIVITY_NO_ANIMATION, minApiLevel = 5),
    FLAG_ACTIVITY_NO_HISTORY(value = Intent.FLAG_ACTIVITY_NO_HISTORY, minApiLevel = 1),
    FLAG_ACTIVITY_NO_USER_ACTION(value = Intent.FLAG_ACTIVITY_NO_USER_ACTION, minApiLevel = 3),
    FLAG_ACTIVITY_PREVIOUS_IS_TOP(value = Intent.FLAG_ACTIVITY_PREVIOUS_IS_TOP, minApiLevel = 1),
    FLAG_ACTIVITY_REQUIRE_DEFAULT(value = Intent.FLAG_ACTIVITY_REQUIRE_DEFAULT, minApiLevel = 34),
    FLAG_ACTIVITY_REQUIRE_NON_BROWSER(value = Intent.FLAG_ACTIVITY_REQUIRE_NON_BROWSER, minApiLevel = 34),
    FLAG_ACTIVITY_RESET_TASK_IF_NEEDED(value = Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED, minApiLevel = 1),
    FLAG_ACTIVITY_RETAIN_IN_RECENTS(value = Intent.FLAG_ACTIVITY_RETAIN_IN_RECENTS, minApiLevel = 21),
    FLAG_ACTIVITY_REORDER_TO_FRONT(value = Intent.FLAG_ACTIVITY_REORDER_TO_FRONT, minApiLevel = 1),
    FLAG_ACTIVITY_SINGLE_TOP(value = Intent.FLAG_ACTIVITY_SINGLE_TOP, minApiLevel = 1),
    FLAG_ACTIVITY_TASK_ON_HOME(value = Intent.FLAG_ACTIVITY_TASK_ON_HOME, minApiLevel = 11),
    FLAG_DEBUG_LOG_RESOLUTION(value = Intent.FLAG_DEBUG_LOG_RESOLUTION, minApiLevel = 1),
    FLAG_DIRECT_BOOT_AUTO(value = Intent.FLAG_DIRECT_BOOT_AUTO, minApiLevel = 24),
    FLAG_EXCLUDE_STOPPED_PACKAGES(value = Intent.FLAG_EXCLUDE_STOPPED_PACKAGES, minApiLevel = 12),
    FLAG_FROM_BACKGROUND(value = Intent.FLAG_FROM_BACKGROUND, minApiLevel = 3),
    FLAG_GRANT_PERSISTABLE_URI_PERMISSION(value = Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION, minApiLevel = 19),
    FLAG_GRANT_PREFIX_URI_PERMISSION(value = Intent.FLAG_GRANT_PREFIX_URI_PERMISSION, minApiLevel = 21),
    FLAG_GRANT_READ_URI_PERMISSION(value = Intent.FLAG_GRANT_READ_URI_PERMISSION, minApiLevel = 1),
    FLAG_GRANT_WRITE_URI_PERMISSION(value = Intent.FLAG_GRANT_WRITE_URI_PERMISSION, minApiLevel = 1),
    FLAG_INCLUDE_STOPPED_PACKAGES(value = Intent.FLAG_INCLUDE_STOPPED_PACKAGES, minApiLevel = 12),
    FLAG_RECEIVER_FOREGROUND(value = Intent.FLAG_RECEIVER_FOREGROUND, minApiLevel = 16),
    FLAG_RECEIVER_NO_ABORT(value = Intent.FLAG_RECEIVER_NO_ABORT, minApiLevel = 19),
    FLAG_RECEIVER_REGISTERED_ONLY(value = Intent.FLAG_RECEIVER_REGISTERED_ONLY, minApiLevel = 1),
    FLAG_RECEIVER_REPLACE_PENDING(value = Intent.FLAG_RECEIVER_REPLACE_PENDING, minApiLevel = 1),
    FLAG_RECEIVER_VISIBLE_TO_INSTANT_APPS(value = Intent.FLAG_RECEIVER_VISIBLE_TO_INSTANT_APPS, minApiLevel = 26),
    ;

    companion object {
        private val byName: Map<String, IntentFlagCatalog> = entries.associateBy { it.name }

        /** Declarative lookup by flag name; returns null for unknown names. */
        fun find(name: String): IntentFlagCatalog? = byName[name]
    }
}
