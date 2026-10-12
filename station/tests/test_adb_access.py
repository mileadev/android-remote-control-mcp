"""Tests for ADB argv allowlisting, inventory collection and port forwards."""

from __future__ import annotations

import unittest

from station.adb_access import (
    FORWARD_BIND_HOST,
    AdbCommandPolicy,
    AdbPolicyError,
    ForwardPolicyError,
    ForwardRegistry,
    collect_inventory,
    parse_binder_services,
    parse_command_services,
    parse_devices,
    parse_features,
)
from station.registry import DeviceRegistry, OperatorApproval

from station.tests.support import DEVICES, enroll_and_make_available

POLL = "interactive"


class ArgsAllowlistTest(unittest.TestCase):
    def setUp(self) -> None:
        self.approval = OperatorApproval(b"0123456789abcdef")
        self.registry = DeviceRegistry(
            {"emulator-5554": POLL, "emulator-5556": POLL}, self.approval
        )
        self.device_id = enroll_and_make_available(
            self.registry, self.approval, DEVICES["pixel"]
        )
        self.policy = AdbCommandPolicy(self.registry)

    def test_getprop_is_allowlisted(self) -> None:
        argv = self.policy.command_argv("emulator-5554", ("shell", "getprop", "ro.build.version.sdk"))
        self.assertEqual(
            ["adb", "-s", "emulator-5554", "shell", "getprop", "ro.build.version.sdk"], argv
        )

    def test_read_only_shell_commands_are_allowlisted(self) -> None:
        for args in (("shell", "id"), ("shell", "pm", "list", "features"),
                     ("shell", "cmd", "-l"), ("shell", "service", "list")):
            argv = self.policy.command_argv("emulator-5554", args)
            self.assertEqual(["adb", "-s", "emulator-5554"], argv[:3])
            self.assertEqual(list(args), argv[3:])

    def test_devices_argv_is_read_only(self) -> None:
        self.assertEqual(["adb", "devices", "-l"], self.policy.devices_argv())

    def test_dangerous_commands_refused(self) -> None:
        for args in (
            ("devices",),
            ("shell", "pm", "install", "/tmp/app.apk"),
            ("shell", "input", "tap", "1", "2"),
            ("shell", "logcat",),
            ("root",),
            ("tcpip", "5555"),
            ("connect", "127.0.0.1:5555"),
            ("install", "/data/x.apk"),
            (),
            ("shell",),
            ("shell", "getprop", "not.a.known.prop.key"),
            ("shell", "getprop"),
            ("shell", "id", "extra"),
        ):
            with self.assertRaises(AdbPolicyError):
                self.policy.command_argv("emulator-5554", args)

    def test_non_string_arguments_refused(self) -> None:
        with self.assertRaises(AdbPolicyError):
            self.policy.command_argv("emulator-5554", ("shell", "getprop", 123))

    def test_unenrolled_and_malformed_serials_refused(self) -> None:
        for serial in ("emulator-9999", "", None, "em-5554; rm -rf /", "-adb-s", "x" * 201):
            with self.assertRaises(AdbPolicyError):
                self.policy.require_enrolled_serial(serial)

    def test_adb_binary_must_be_plain(self) -> None:
        with self.assertRaises(ValueError):
            AdbCommandPolicy(self.registry, adb_binary="-flag")
        with self.assertRaises(ValueError):
            AdbCommandPolicy(self.registry, adb_binary="")


class ParseTest(unittest.TestCase):
    def test_parse_devices_states(self) -> None:
        listed = parse_devices(
            "List of devices attached\n"
            "emulator-5554 device product:x model:y device:emulator-5554 transport_id:1\n"
            "emulator-5556 offline transport_id:2\n"
            "emulator-5558 unauthorized transport_id:3\n"
            "recovery-abc recovery transport_id:4\n"
        )
        self.assertEqual(
            {
                "emulator-5554": "device",
                "emulator-5556": "offline",
                "emulator-5558": "unauthorized",
                "recovery-abc": "recovery",
            },
            listed,
        )

    def test_parse_devices_ignores_junk(self) -> None:
        self.assertEqual({}, parse_devices("List of devices attached\n\n"))
        self.assertEqual({}, parse_devices("* daemon not running\nsome text line\n"))

    def test_parse_features(self) -> None:
        raw = "feature:android.hardware.camera\nfeature:android.hardware.wifi\nfeature:android.hardware.camera\nnoise\n"
        self.assertEqual(
            ["android.hardware.camera", "android.hardware.wifi"], parse_features(raw)
        )

    def test_parse_binder_services(self) -> None:
        raw = "  1234 phone: 325378\n  555 window: 325511\ngarbage without pid\n"
        self.assertEqual(["phone", "window"], parse_binder_services(raw))

    def test_parse_command_services(self) -> None:
        raw = "Currently running services:\nactivity\nwindow\n  indented garbage!\n"
        self.assertEqual(["activity", "window"], parse_command_services(raw))


class InventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.approval = OperatorApproval(b"0123456789abcdef")
        self.registry = DeviceRegistry({"emulator-5554": POLL}, self.approval)
        enroll_and_make_available(self.registry, self.approval, DEVICES["pixel"])
        self.policy = AdbCommandPolicy(self.registry)
        self.seen: list[list[str]] = []

    def _runner(self, argv, timeout):
        self.seen.append(list(argv))
        joined = " ".join(argv)
        if "devices" in joined:
            return (0, "List of devices attached\nemulator-5554 device transport_id:1\n", "")
        if "getprop" in joined:
            return (0, "34\n", "")
        if "pm list features" in joined:
            return (0, "feature:android.hardware.wifi\n", "")
        if "cmd -l" in joined:
            return (0, "Currently running services:\nactivity\n", "")
        if "service list" in joined:
            return (0, "  555 window: 100\n", "")
        if "id" in joined:
            return (0, "uid=2000(shell) gid=2000(shell)\n", "")
        return (1, "", "unknown command")

    def test_collect_inventory_happy_path(self) -> None:
        inventory = collect_inventory(
            "emulator-5554", self.policy, runner=self._runner, timeout=5
        )
        self.assertEqual("device", inventory["adb_state"])
        self.assertEqual("34", inventory["props"]["ro.build.version.sdk"])
        self.assertEqual(["android.hardware.wifi"], inventory["hardware_features"])
        self.assertEqual(["window"], inventory["binder_services"])
        self.assertEqual({"activity"}, set(inventory["command_services"]))
        self.assertEqual({}, inventory["errors"])
        for argv in self.seen:
            self.assertEqual("adb", argv[0])
            if "devices" in argv:
                continue
            self.assertIn("-s", argv)

    def test_collect_inventory_reports_query_failures(self) -> None:
        def runner(argv, timeout):
            joined = " ".join(argv)
            if "devices" in joined:
                return (0, "List of devices attached\nemulator-5554 device transport_id:1\n", "")
            return (1, "", "unsupported")

        inventory = collect_inventory("emulator-5554", self.policy, runner=runner)
        self.assertTrue(inventory["errors"])
        self.assertEqual([], inventory["hardware_features"])

    def test_collect_inventory_refuses_unlisted_serial(self) -> None:
        def runner(argv, timeout):
            return (0, "List of devices attached\nemulator-9999 device transport_id:1\n", "")

        with self.assertRaisesRegex(RuntimeError, "unlisted serial"):
            collect_inventory("emulator-5554", self.policy, runner=runner)

    def test_collect_inventory_refuses_offline_state(self) -> None:
        def runner(argv, timeout):
            return (0, "List of devices attached\nemulator-5554 offline transport_id:1\n", "")

        with self.assertRaisesRegex(RuntimeError, "authorized online state"):
            collect_inventory("emulator-5554", self.policy, runner=runner)

    def test_collect_inventory_propagates_devices_failure(self) -> None:
        def runner(argv, timeout):
            return (1, "", "adb: no devices")

        with self.assertRaisesRegex(RuntimeError, "adb devices failed"):
            collect_inventory("emulator-5554", self.policy, runner=runner)

    def test_collect_inventory_timeout_bounds(self) -> None:
        for bad in (0, 31, -1, 1.5, True, "3"):
            with self.assertRaises(ValueError):
                collect_inventory("emulator-5554", self.policy, runner=self._runner, timeout=bad)


class ForwardPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.approval = OperatorApproval(b"0123456789abcdef")
        self.registry = DeviceRegistry(
            {"emulator-5554": POLL, "emulator-5556": POLL}, self.approval
        )
        enroll_and_make_available(self.registry, self.approval, DEVICES["pixel"])
        enroll_and_make_available(self.registry, self.approval, DEVICES["second"])
        self.forwards = ForwardRegistry(self.registry)

    def test_add_get_snapshot(self) -> None:
        self.forwards.add("dev-pixel", 18000, "tcp:8080")
        self.assertEqual({18000: "tcp:8080"}, self.forwards.get("dev-pixel"))
        self.assertEqual(
            {"dev-pixel": {18000: "tcp:8080"}}, self.forwards.snapshot()
        )
        self.assertEqual(FORWARD_BIND_HOST, "127.0.0.1")

    def test_forbidden_ports_refused_everywhere(self) -> None:
        for host_port in (5037, 5555, 1019, 65536, 0, -1):
            with self.assertRaises(ForwardPolicyError):
                self.forwards.add("dev-pixel", host_port, "tcp:8080")
        for target in ("tcp:5037", "tcp:5555", "tcp:0", "tcp:65536", "tcp:abc",
                       "http:8080", "unix:/tmp/sock", "tcp:", "tcp:007x"):
            with self.assertRaises(ForwardPolicyError):
                self.forwards.add("dev-pixel", 18000, target)

    def test_host_port_unique_across_devices(self) -> None:
        self.forwards.add("dev-pixel", 18000, "tcp:8080")
        with self.assertRaisesRegex(ForwardPolicyError, "must be unique per device"):
            self.forwards.add("dev-second", 18000, "tcp:9090")

    def test_idempotent_re_add_same_target(self) -> None:
        self.forwards.add("dev-pixel", 18000, "tcp:8080")
        self.forwards.add("dev-pixel", 18000, "tcp:8080")
        self.assertEqual({18000: "tcp:8080"}, self.forwards.get("dev-pixel"))

    def test_conflicting_re_add_refused(self) -> None:
        self.forwards.add("dev-pixel", 18000, "tcp:8080")
        with self.assertRaisesRegex(ForwardPolicyError, "already forwards"):
            self.forwards.add("dev-pixel", 18000, "tcp:9090")

    def test_remove_and_remove_device(self) -> None:
        self.forwards.add("dev-pixel", 18000, "tcp:8080")
        self.forwards.add("dev-pixel", 18001, "tcp:8081")
        self.forwards.remove("dev-pixel", 18001)
        self.assertEqual({18000: "tcp:8080"}, self.forwards.get("dev-pixel"))
        self.forwards.remove_device("dev-pixel")
        self.assertEqual({}, self.forwards.get("dev-pixel"))
        with self.assertRaises(ForwardPolicyError):
            self.forwards.remove("dev-second", 18000)

    def test_forward_requires_enrolled_device(self) -> None:
        with self.assertRaisesRegex(ForwardPolicyError, "not enrolled"):
            self.forwards.add("dev-unknown", 18000, "tcp:8080")

    def test_multiple_devices_own_ports(self) -> None:
        self.forwards.add("dev-pixel", 18000, "tcp:8080")
        self.forwards.add("dev-second", 18001, "tcp:8080")
        self.assertEqual(
            {"dev-pixel": {18000: "tcp:8080"}, "dev-second": {18001: "tcp:8080"}},
            self.forwards.snapshot(),
        )


if __name__ == "__main__":
    unittest.main()
