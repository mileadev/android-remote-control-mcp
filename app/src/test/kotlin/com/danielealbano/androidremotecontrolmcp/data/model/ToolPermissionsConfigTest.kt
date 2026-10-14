package com.danielealbano.androidremotecontrolmcp.data.model

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("ToolPermissionsConfig")
class ToolPermissionsConfigTest {
    @Test
    fun `isToolEnabled returns true for empty disabledTools`() {
        val config = ToolPermissionsConfig()
        assertTrue(config.isToolEnabled("tap"))
    }

    @Test
    fun `isToolEnabled returns false when tool is in disabledTools`() {
        val config = ToolPermissionsConfig(disabledTools = setOf("tap"))
        assertFalse(config.isToolEnabled("tap"))
    }

    @Test
    fun `isToolEnabled returns true for unknown tool names`() {
        val config = ToolPermissionsConfig(disabledTools = setOf("nonexistent_tool"))
        assertTrue(config.isToolEnabled("tap"))
    }

    @Test
    fun `isParamEnabled returns true for empty disabledParams`() {
        val config = ToolPermissionsConfig()
        assertTrue(config.isParamEnabled("get_screen_state", "include_screenshot"))
    }

    @Test
    fun `isParamEnabled returns false when param is in disabledParams`() {
        val config =
            ToolPermissionsConfig(
                disabledParams = mapOf("get_screen_state" to setOf("include_screenshot")),
            )
        assertFalse(config.isParamEnabled("get_screen_state", "include_screenshot"))
    }

    @Test
    fun `isParamEnabled returns true when tool has no entry`() {
        val config =
            ToolPermissionsConfig(
                disabledParams = mapOf("get_screen_state" to setOf("include_screenshot")),
            )
        assertTrue(config.isParamEnabled("save_camera_video", "audio"))
    }

    @Test
    fun `toJson with empty config produces expected JSON`() {
        val json = ToolPermissionsConfig().toJson()
        assertEquals("{\"disabledTools\":[],\"disabledParams\":{}}", json)
    }

    @Test
    fun `toJson and fromJson round-trip`() {
        val original =
            ToolPermissionsConfig(
                disabledTools = setOf("tap", "swipe"),
                disabledParams = mapOf("get_screen_state" to setOf("include_screenshot")),
            )
        val json = original.toJson()
        val restored = ToolPermissionsConfig.fromJson(json)
        assertNotNull(restored)
        assertEquals(original, restored)
    }

    @Test
    fun `fromJson with empty JSON object`() {
        val config = ToolPermissionsConfig.fromJson("{}")
        assertNotNull(config)
        assertEquals(ToolPermissionsConfig(), config)
    }

    @Test
    fun `fromJson with valid JSON`() {
        val json =
            """{"disabledTools":["tap","swipe"],"disabledParams":{"get_screen_state":["include_screenshot"]}}"""
        val config = ToolPermissionsConfig.fromJson(json)
        assertNotNull(config)
        assertEquals(setOf("tap", "swipe"), config!!.disabledTools)
        assertEquals(
            mapOf("get_screen_state" to setOf("include_screenshot")),
            config.disabledParams,
        )
    }

    @Test
    fun `fromJson with invalid JSON returns null`() {
        assertNull(ToolPermissionsConfig.fromJson("not json"))
    }

    @Test
    fun `fromJsonOrDefault with null returns default`() {
        val config = ToolPermissionsConfig.fromJsonOrDefault(null)
        assertEquals(ToolPermissionsConfig(), config)
    }

    @Test
    fun `fromJsonOrDefault with invalid JSON returns default`() {
        val config = ToolPermissionsConfig.fromJsonOrDefault("not json")
        assertEquals(ToolPermissionsConfig(), config)
    }

    @Test
    fun `fromJson with unknown extra JSON keys`() {
        val json =
            """{"disabledTools":["tap"],"disabledParams":{},"unknownKey":"value"}"""
        val config = ToolPermissionsConfig.fromJson(json)
        assertNotNull(config)
        assertEquals(setOf("tap"), config!!.disabledTools)
    }

    @Test
    fun `fromJson with partially valid JSON`() {
        val json = """{"disabledTools":["tap"],"disabledParams":"not_an_object"}"""
        val config = ToolPermissionsConfig.fromJson(json)
        assertNull(config)
    }

    @Nested
    @DisplayName("fromJsonForPolicy fail closed")
    inner class FailClosedPolicy {
        private fun parse(json: String?): ToolPermissionsConfig =
            ToolPermissionsConfig.fromJsonForPolicy(json, ToolPermissionsConfig.PolicyMode.FAIL_CLOSED)

        @Test
        fun `null JSON resolves to DENY_ALL`() {
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(null))
            assertFalse(parse(null).isToolEnabled("tap"))
        }

        @Test
        fun `corrupt JSON resolves to DENY_ALL`() {
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse("{ corrupted"))
        }

        @Test
        fun `truncated JSON resolves to DENY_ALL`() {
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse("""{"schemaVersion":1,"allowedToolIds":["tap""""))
        }

        @Test
        fun `empty object resolves to DENY_ALL`() {
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse("{}"))
        }

        @Test
        fun `unknown schema version resolves to DENY_ALL`() {
            val json = """{"schemaVersion":2,"allowedToolIds":["tap"],"disabledParams":{}}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `missing allowedToolIds resolves to DENY_ALL`() {
            val json = """{"schemaVersion":1,"disabledParams":{}}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `missing disabledParams resolves to DENY_ALL`() {
            val json = """{"schemaVersion":1,"allowedToolIds":["tap"]}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `non-string allowlist entries resolve to DENY_ALL`() {
            val json = """{"schemaVersion":1,"allowedToolIds":[42],"disabledParams":{}}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `JSON null allowlist entries resolve to DENY_ALL`() {
            val json = """{"schemaVersion":1,"allowedToolIds":[null],"disabledParams":{}}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `non-string disabledParams entries resolve to DENY_ALL`() {
            val json = """{"schemaVersion":1,"allowedToolIds":[],"disabledParams":{"tap":[42]}}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `non-object disabledParams value resolves to DENY_ALL`() {
            val json = """{"schemaVersion":1,"allowedToolIds":[],"disabledParams":{"tap":"x"}}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `unknown keys resolve to DENY_ALL`() {
            val json =
                """{"schemaVersion":1,"allowedToolIds":["tap"],"disabledParams":{},"unknownKey":"value"}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `upstream format document without schemaVersion resolves to DENY_ALL`() {
            val json = """{"disabledTools":["tap"],"disabledParams":{}}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `valid policy document parses allowlist disabledParams and disabledTools`() {
            val json =
                """{"schemaVersion":1,"allowedToolIds":["tap","long_press"],"disabledParams":""" +
                    """{"tap":["x"]},"disabledTools":["swipe"]}"""
            val config = parse(json)
            assertEquals(
                ToolPermissionsConfig(
                    disabledTools = setOf("swipe"),
                    disabledParams = mapOf("tap" to setOf("x")),
                    allowedToolIds = setOf("tap", "long_press"),
                ),
                config,
            )
            assertTrue(config.isToolEnabled("tap"))
            assertTrue(config.isToolEnabled("long_press"))
            assertFalse(config.isToolEnabled("swipe"))
            assertFalse(config.isToolEnabled("unlisted"))
        }

        @Test
        fun `minimal valid policy document equals DENY_ALL`() {
            val json = """{"schemaVersion":1,"allowedToolIds":[],"disabledParams":{}}"""
            assertEquals(ToolPermissionsConfig.DENY_ALL, parse(json))
        }

        @Test
        fun `hardened toJson emits versioned policy document`() {
            val config =
                ToolPermissionsConfig(
                    disabledParams = mapOf("tap" to setOf("x")),
                    allowedToolIds = setOf("long_press"),
                )
            val json = config.toJson()
            assertEquals(
                """{"schemaVersion":1,"allowedToolIds":["long_press"],"disabledParams":""" +
                    """{"tap":["x"]},"disabledTools":[]}""",
                json,
            )
        }

        @Test
        fun `hardened toJson round-trips through fail closed parse`() {
            val original =
                ToolPermissionsConfig(
                    disabledTools = setOf("swipe"),
                    disabledParams = mapOf("tap" to setOf("hold")),
                    allowedToolIds = setOf("tap"),
                )
            assertEquals(original, parse(original.toJson()))
        }

        @Test
        fun `DENY_ALL denies every tool and parameter`() {
            val config = ToolPermissionsConfig.DENY_ALL
            assertFalse(config.isToolEnabled("tap"))
            assertFalse(config.isToolEnabled("get_screen_state"))
            assertFalse(config.isParamEnabled("tap", "x"))
        }

        @Test
        fun `allowlist ANDs with disabledTools`() {
            val config =
                ToolPermissionsConfig(
                    disabledTools = setOf("tap"),
                    allowedToolIds = setOf("tap", "swipe"),
                )
            assertFalse(config.isToolEnabled("tap"))
            assertTrue(config.isToolEnabled("swipe"))
            assertFalse(config.isParamEnabled("tap", "x"))
            assertTrue(config.isParamEnabled("swipe", "x"))
        }

        @Test
        fun `params of non-allowlisted tools are denied`() {
            val config = ToolPermissionsConfig(allowedToolIds = setOf("tap"))
            assertFalse(config.isParamEnabled("swipe", "x"))
            assertTrue(config.isParamEnabled("tap", "x"))
        }

        @Test
        fun `permissive default mode keeps the upstream fallback`() {
            val corrupt = "{ corrupted"
            val valid = """{"disabledTools":["tap"],"disabledParams":{}}"""
            val mode = ToolPermissionsConfig.PolicyMode.PERMISSIVE_DEFAULT
            assertEquals(
                ToolPermissionsConfig.fromJsonOrDefault(null),
                ToolPermissionsConfig.fromJsonForPolicy(null, mode),
            )
            assertEquals(
                ToolPermissionsConfig.fromJsonOrDefault(corrupt),
                ToolPermissionsConfig.fromJsonForPolicy(corrupt, mode),
            )
            assertEquals(
                ToolPermissionsConfig.fromJsonOrDefault(valid),
                ToolPermissionsConfig.fromJsonForPolicy(valid, mode),
            )
        }

        @Test
        fun `original fromJsonOrDefault still resolves upstream format`() {
            val json = """{"disabledTools":["tap"],"disabledParams":{}}"""
            val config = ToolPermissionsConfig.fromJsonOrDefault(json)
            assertEquals(ToolPermissionsConfig(disabledTools = setOf("tap")), config)
            assertTrue(config.isToolEnabled("swipe"))
        }
    }
}
