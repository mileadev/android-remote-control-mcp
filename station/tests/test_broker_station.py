"""The acceptance-gate test suite for the hardened lab station broker.

The class name and method names map directly to the BrokerStationTest gate
from the handoff acceptance document: serialMustBeExplicitAndEnrolled,
deviceLeaseIsExclusiveAndFenced, toolBlockedAtStationEvenIfGatewayAllows,
staleDeviceMismatchedLeaseDenied, timeoutDoesNotReplayNonIdempotentTap and
atsOwnedDeviceUnavailableToInteractiveWorker.
"""

from __future__ import annotations

import unittest

from station.broker import ATS_IDENTITY, BrokerError
from station.drivers import RecordingDeviceDriver, DriverResponse
from station.leases import DeviceBusy
from station.registry import Caller

from station.tests.support import (
    DEVICES,
    FakeClock,
    build_broker,
    build_registry,
    enroll_and_make_available,
    make_caller,
)

POLL = "interactive"


def fake_adb_runner(argv, timeout):
    """Deterministic read-only ADB output covering the inventory calls."""
    joined = " ".join(argv)
    if "devices" in joined:
        return (
            0,
            "List of devices attached\n"
            "emulator-5554 device transport_id:1\n"
            "emulator-5556 device transport_id:2\n"
            "R3CTEST00DEVICE device transport_id:3\n"
            "emulator-5558 device transport_id:4\n",
            "",
        )
    if "getprop" in joined:
        return (0, "35\n", "")
    if "pm list features" in joined:
        return (0, "feature:android.hardware.wifi\n", "")
    if "cmd -l" in joined:
        return (0, "Currently running services:\nactivity\n", "")
    if "service list" in joined:
        return (0, "  555 window: 100\n", "")
    if "id" in joined:
        return (0, "uid=2000(shell) gid=2000(shell)\n", "")
    return (1, "", "unknown command")


def acquire_via(broker, leasing, caller: Caller, device_id: str) -> dict:
    response = broker.execute(
        caller,
        "android.sessions.acquire",
        {
            "request_id": f"acq-{caller.identity}-{device_id}",
            "device_id": device_id,
        },
    )
    assert response["status"] == "completed", response.get("error")
    return {
        "lease_id": response["result"]["lease_id"],
        "lease_generation": response["result"]["lease_generation"],
    }


class BrokerStationTest(unittest.TestCase):
    """One broker wired to three enrolled devices across pools."""

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.registry, self.approval = build_registry()
        self.driver = RecordingDeviceDriver(
            responses={
                "android.ui.observe": DriverResponse(
                    status="completed",
                    result={"window": "MainActivity"},
                    tree_generation=11,
                ),
                "android.ui.batch": DriverResponse(
                    status="completed",
                    result={"steps_done": 1},
                    tree_generation=12,
                ),
            }
        )
        for spec in DEVICES.values():
            enroll_and_make_available(self.registry, self.approval, spec)
        self.broker, self.leasing = build_broker(
            self.clock,
            registry=self.registry,
            driver=self.driver,
            adb_runner=fake_adb_runner,
            preapproved_tests=frozenset({"com.example.Suite#testLogin"}),
        )
        self.alice = make_caller(
            "alice", ("operator", "observer"), ("dev-pixel", "dev-second")
        )
        self.bob = make_caller("bob", ("observer",), ("dev-pixel",))
        self.charlie = make_caller(
            "charlie", ("operator",), ("dev-pixel", "dev-second")
        )
        self.ci = make_caller("ci-bot", ("test-runner",), ("dev-second", "dev-sched"))

    def _acquire(self, caller: Caller, device_id: str) -> dict:
        return acquire_via(self.broker, self.leasing, caller, device_id)

    def _observe(self, caller: Caller, device_id: str, lease: dict, *, request_id: str = "req-observe", arguments: dict | None = None, idempotency_key: str = "observe-key-1", deadline_ms: int = 5000, execute_on=None) -> dict:
        envelope = {
            "request_id": request_id,
            "device_id": device_id,
            "lease_id": lease["lease_id"],
            "lease_generation": lease["lease_generation"],
            "arguments": arguments or {},
            "idempotency_key": idempotency_key,
            "deadline_ms": deadline_ms,
        }
        broker = execute_on or self.broker
        return broker.execute(caller, "android.ui.observe", envelope)

    # -------------------------------------------------- gate: explicit serial

    def test_serial_must_be_explicit_and_enrolled(self) -> None:
        response = self.broker.execute(
            self.alice,
            "android.devices.capabilities",
            {"request_id": "cap-unenrolled", "device_id": "dev-unknown"},
        )
        self.assertEqual("denied", response["status"])
        self.assertIn("device rejected", response["error"])

        operator_view = self.broker.execute(
            self.alice,
            "android.devices.capabilities",
            {"request_id": "cap-enrolled", "device_id": "dev-pixel"},
        )
        self.assertEqual("completed", operator_view["status"])
        self.assertEqual("emulator-5554", operator_view["result"]["serial"])
        self.assertEqual("35", operator_view["result"]["props"]["ro.build.version.sdk"])

        observer_view = self.broker.execute(
            self.bob,
            "android.devices.capabilities",
            {"request_id": "cap-observer", "device_id": "dev-pixel"},
        )
        self.assertEqual("completed", observer_view["status"])
        self.assertIsNone(observer_view["result"]["serial"])
        self.assertNotIn("ro.build.fingerprint", observer_view["result"]["props"])

        listing = self.broker.execute(
            self.bob, "android.devices.list", {"request_id": "list-bob"}
        )
        self.assertEqual("completed", listing["status"])
        ids = {device["device_id"] for device in listing["result"]["devices"]}
        self.assertEqual({"dev-pixel"}, ids)
        for device in listing["result"]["devices"]:
            self.assertNotIn("serial", device)

    # ------------------------------------------------- gate: exclusive + fence

    def test_device_lease_is_exclusive_and_fenced(self) -> None:
        lease = self._acquire(self.alice, "dev-pixel")
        with self.assertRaises(DeviceBusy):
            self.leasing.acquire("dev-pixel", "bob")
        busy = self.broker.execute(
            self.bob,
            "android.sessions.acquire",
            {"request_id": "bob-busy", "device_id": "dev-pixel"},
        )
        self.assertEqual("denied", busy["status"])

        observed = self._observe(self.alice, "dev-pixel", lease)
        self.assertEqual("completed", observed["status"])
        self.assertEqual(11, observed["tree_generation"])

        renewed = self.broker.execute(
            self.alice,
            "android.sessions.renew",
            {
                "request_id": "renew-1",
                "device_id": "dev-pixel",
                "lease_id": lease["lease_id"],
                "lease_generation": lease["lease_generation"],
            },
        )
        self.assertEqual("completed", renewed["status"])

        released = self.broker.execute(
            self.alice,
            "android.sessions.release",
            {
                "request_id": "release-1",
                "device_id": "dev-pixel",
                "lease_id": lease["lease_id"],
                "lease_generation": lease["lease_generation"],
            },
        )
        self.assertEqual("completed", released["status"])
        self.assertTrue(released["result"]["released"])
        self.assertEqual("AVAILABLE", self.registry.state("dev-pixel"))
        reacquired = self._acquire(self.alice, "dev-pixel")
        self.assertGreater(
            reacquired["lease_generation"], lease["lease_generation"]
        )

    # ------------------------------------------- gate: tool blocked at station

    def test_tool_blocked_at_station_even_if_gateway_allows(self) -> None:
        for operation, role in (
            ("android.video.session", "human-viewer"),
            ("android.logs.query", "investigator"),
        ):
            viewer = make_caller(f"watcher-{role}", (role,), ("dev-pixel",))
            response = self.broker.execute(
                viewer,
                operation,
                {"request_id": f"blocked-{operation}", "device_id": "dev-pixel"},
            )
            self.assertEqual("unsupported", response["status"], operation)

        unknown = self.broker.execute(
            self.alice,
            "android.window.wipe",
            {"request_id": "blocked-unknown", "device_id": "dev-pixel"},
        )
        self.assertEqual("denied", unknown["status"])

        wrong_role = self.broker.execute(
            self.bob,
            "android.sessions.acquire",
            {"request_id": "role-acq", "device_id": "dev-pixel"},
        )
        self.assertEqual("denied", wrong_role["status"])
        self.assertIn("role", wrong_role["error"])

        unscoped = make_caller("dave", ("operator",), ("dev-other-only",))
        scope_fail = self.broker.execute(
            unscoped,
            "android.sessions.acquire",
            {"request_id": "scope-acq", "device_id": "dev-pixel"},
        )
        self.assertEqual("denied", scope_fail["status"])

    # ------------------------------------------------ gate: stale and mismatch

    def test_stale_device_mismatched_lease_denied(self) -> None:
        lease_pixel = self._acquire(self.alice, "dev-pixel")
        lease_second = self._acquire(self.alice, "dev-second")

        mismatched = self._observe(
            self.alice, "dev-second", lease_pixel, request_id="req-mismatch"
        )
        self.assertEqual("denied", mismatched["status"])
        self.assertIn("different device", mismatched["error"])

        stale = self._observe(
            self.alice,
            "dev-pixel",
            {"lease_id": lease_pixel["lease_id"], "lease_generation": 99},
            request_id="req-stale",
        )
        self.assertEqual("denied", stale["status"])
        self.assertIn("stale", stale["error"])

        caller_mismatch = self._observe(
            self.charlie, "dev-pixel", lease_pixel, request_id="req-caller-mismatch",
            idempotency_key="k-mismatch-caller",
        )
        self.assertEqual("denied", caller_mismatch["status"])
        self.assertIn("different caller", caller_mismatch["error"])

        crossed = self._observe(
            self.alice,
            "dev-second",
            {
                "lease_id": lease_second["lease_id"],
                "lease_generation": lease_pixel["lease_generation"] + 10,
            },
            request_id="req-cross-device",
        )
        self.assertEqual("denied", crossed["status"])
        self.assertEqual(0, len(self.driver.calls))

    # ----------------------------------------- gate: timeout, no replay of tap

    def test_timeout_does_not_replay_non_idempotent_tap(self) -> None:
        slow_driver = RecordingDeviceDriver(simulated_duration_ms=10_000)
        broker, leasing = build_broker(
            self.clock, registry=self.registry, driver=slow_driver
        )
        lease = acquire_via(broker, leasing, self.alice, "dev-pixel")
        envelope = {
            "request_id": "tap-1",
            "device_id": "dev-pixel",
            "lease_id": lease["lease_id"],
            "lease_generation": lease["lease_generation"],
            "deadline_ms": 100,
            "arguments": {"steps": [{"action": "tap", "x": 100, "y": 200}]},
            "idempotency_key": "tap-key-7",
        }
        timed_out = broker.execute(self.alice, "android.ui.batch", envelope)
        self.assertEqual("unknown_outcome", timed_out["status"])
        self.assertEqual(1, len(slow_driver.calls))

        replay = broker.execute(
            self.alice, "android.ui.batch", dict(envelope, request_id="tap-2")
        )
        self.assertEqual("unknown_outcome", replay["status"])
        self.assertEqual(1, len(slow_driver.calls), "retry must not re-execute the tap")

        second_key = broker.execute(
            self.alice,
            "android.ui.batch",
            dict(envelope, request_id="tap-3", idempotency_key="tap-key-8"),
        )
        self.assertEqual("unknown_outcome", second_key["status"])
        self.assertEqual(2, len(slow_driver.calls))

    # ------------------------------------------ gate: ATS-owned device shield

    def test_ats_owned_device_unavailable_to_interactive_worker(self) -> None:
        submitted = self.broker.execute(
            self.ci,
            "android.tests.submit",
            {
                "request_id": "submit-1",
                "device_id": "dev-sched",
                "arguments": {"test_name": "com.example.Suite#testLogin"},
            },
        )
        self.assertEqual("completed", submitted["status"], submitted.get("error"))
        result = submitted["result"]
        self.assertEqual(ATS_IDENTITY, self.leasing.active_lease("dev-sched").caller)

        attempt = self.broker.execute(
            self.alice,
            "android.sessions.acquire",
            {"request_id": "acq-ats-owned", "device_id": "dev-sched"},
        )
        self.assertEqual("denied", attempt["status"])
        self.assertIn("automated test scheduler", attempt["error"])

        wrong_submitter = make_caller("other-ci", ("test-runner",), ("dev-sched",))
        status_other = self.broker.execute(
            wrong_submitter,
            "android.tests.status",
            {
                "request_id": "status-other",
                "device_id": "dev-sched",
                "arguments": {"job_id": result["job_id"]},
            },
        )
        self.assertEqual("denied", status_other["status"])

        status_own = self.broker.execute(
            self.ci,
            "android.tests.status",
            {
                "request_id": "status-own",
                "device_id": "dev-sched",
                "arguments": {"job_id": result["job_id"]},
            },
        )
        self.assertEqual("completed", status_own["status"])
        self.assertEqual("queued", status_own["result"]["status"])

        self.broker.complete_job(result["job_id"])
        self.assertEqual("AVAILABLE", self.registry.state("dev-sched"))
        self.assertIsNone(self.leasing.active_lease("dev-sched"))

        unpreapproved = self.broker.execute(
            self.ci,
            "android.tests.submit",
            {
                "request_id": "submit-2",
                "device_id": "dev-sched",
                "arguments": {"test_name": "com.example.Suite#testNotApproved"},
            },
        )
        self.assertEqual("denied", unpreapproved["status"])

    # ------------------------------------------------------- additional gates

    def test_quarantined_device_denied_even_with_previously_valid_lease(self) -> None:
        lease = self._acquire(self.alice, "dev-pixel")
        self.registry.quarantine("dev-pixel", "suspected tampering")
        response = self._observe(self.alice, "dev-pixel", lease, request_id="req-quarantine")
        self.assertEqual("denied", response["status"])
        self.assertIn("quarantined", response["error"])
        self.assertEqual(0, len(self.driver.calls))
        capabilities = self.broker.execute(
            self.alice,
            "android.devices.capabilities",
            {"request_id": "cap-quarantine", "device_id": "dev-pixel"},
        )
        self.assertEqual("denied", capabilities["status"])

    def test_catalog_revision_mismatch_is_denied(self) -> None:
        response = self.broker.execute(
            self.alice,
            "android.devices.list",
            {"request_id": "req-old-catalog", "catalog_revision": "sha256:0"},
        )
        self.assertEqual("denied", response["status"])
        self.assertIn("catalog", response["error"])

    def test_faulty_station_backend_denies_by_policy(self) -> None:
        class ExplodingLeaseTable:
            def expire_due(self):
                return ()

            def active_lease(self, device_id):
                return None

            def validate(self, **_kwargs):
                raise RuntimeError("backend exploded")

            def generation(self, device_id):
                raise RuntimeError("backend exploded")

        broker, _leasing = build_broker(
            FakeClock(), registry=self.registry, leasing=ExplodingLeaseTable()
        )
        listing = broker.execute(
            self.alice, "android.devices.list", {"request_id": "req-broken-list"}
        )
        self.assertEqual("completed", listing["status"])
        operation = broker.execute(
            self.alice,
            "android.ui.observe",
            {
                "request_id": "req-broken-driver",
                "device_id": "dev-pixel",
                "lease_id": "lease-0001",
                "lease_generation": 1,
                "arguments": {},
                "idempotency_key": "broken-key",
            },
        )
        self.assertEqual("denied", operation["status"])
        self.assertIn("backend unavailable", operation["error"])

    def test_audit_records_no_arguments_or_secrets(self) -> None:
        lease = self._acquire(self.alice, "dev-pixel")
        self._observe(
            self.alice, "dev-pixel", lease, arguments={"tree_max_depth": 3}
        )
        events = self.broker.audit_events()
        self.assertTrue(events)
        for event in events:
            self.assertEqual(
                {
                    "request_id",
                    "caller",
                    "operation_id",
                    "device_id",
                    "status",
                    "timestamp_utc",
                },
                set(event),
            )

    def test_replay_returns_recorded_outcome_without_driver_call(self) -> None:
        lease = self._acquire(self.alice, "dev-pixel")
        first = self._observe(self.alice, "dev-pixel", lease, request_id="req-one")
        self.assertEqual("completed", first["status"])
        driver_calls = len(self.driver.calls)
        second = self._observe(self.alice, "dev-pixel", lease, request_id="req-two")
        self.assertEqual("completed", second["status"])
        self.assertEqual(first["result"], second["result"])
        self.assertEqual("req-two", second["request_id"])
        self.assertEqual(driver_calls, len(self.driver.calls))

    def test_lease_expiry_mid_operation_yields_unknown_outcome(self) -> None:
        timing_driver = RecordingDeviceDriver(
            responses={
                "android.ui.batch": DriverResponse("completed", {"steps_done": 1}, 22)
            },
            on_perform=lambda *_args: self.clock.advance(3600),
        )
        broker, leasing = build_broker(
            self.clock, registry=self.registry, driver=timing_driver
        )
        lease = acquire_via(broker, leasing, self.alice, "dev-pixel")
        envelope = {
            "request_id": "req-midtap",
            "device_id": "dev-pixel",
            "lease_id": lease["lease_id"],
            "lease_generation": lease["lease_generation"],
            "deadline_ms": 60000,
            "arguments": {"steps": [{"action": "tap", "x": 1, "y": 2}]},
            "idempotency_key": "midtap-key",
        }
        response = broker.execute(self.alice, "android.ui.batch", envelope)
        self.assertEqual("unknown_outcome", response["status"], response.get("error"))
        retry = broker.execute(
            self.alice, "android.ui.batch", dict(envelope, request_id="req-midtap-2")
        )
        self.assertEqual("denied", retry["status"])

    def test_mutating_operations_require_idempotency_key(self) -> None:
        lease = self._acquire(self.alice, "dev-pixel")
        with self.assertRaises(BrokerError):
            self.broker.execute(
                self.alice,
                "android.ui.batch",
                {
                    "request_id": "req-noidem",
                    "device_id": "dev-pixel",
                    "lease_id": lease["lease_id"],
                    "lease_generation": lease["lease_generation"],
                    "arguments": {"steps": [{"action": "tap", "x": 1, "y": 2}]},
                },
            )

    def test_deadline_bounds_are_enforced(self) -> None:
        lease = self._acquire(self.alice, "dev-pixel")
        for deadline in (49, 60001, 0, -5):
            with self.assertRaises(BrokerError):
                self._observe(self.alice, "dev-pixel", lease, deadline_ms=deadline)

    def test_api_describe_returns_catalog(self) -> None:
        describe = self.broker.execute(
            self.bob, "android.api.describe", {"request_id": "req-describe"}
        )
        self.assertEqual("completed", describe["status"])
        result = describe["result"]
        self.assertIn("android.wifi.read_connection_info.v1", result["catalog"])
        self.assertEqual(self.broker.catalog_revision, result["catalog_revision"])
        self.assertIn("android.devices.list", result["supported_operations"])

    def test_privileged_pool_needs_operator_role(self) -> None:
        registry, approval = build_registry()
        allowlist = dict(registry.allowlist)
        allowlist["emulator-5558"] = "privileged"
        from station.registry import DeviceRegistry

        registry = DeviceRegistry(allowlist, approval)
        enroll_and_make_available(
            registry, approval, ("emulator-5558", "dev-priv", "fp-priv")
        )
        broker, leasing = build_broker(
            self.clock, registry=registry, driver=self.driver, adb_runner=fake_adb_runner
        )
        denied_view = broker.execute(
            make_caller(
                "looker", ("observer",), ("dev-priv",)
            ),
            "android.devices.capabilities",
            {"request_id": "cap-priv-obs", "device_id": "dev-priv"},
        )
        self.assertEqual("denied", denied_view["status"])
        self.assertIn("operator", denied_view["error"])
        operator = make_caller(
            "root-hands", ("operator", "observer"), ("dev-priv",)
        )
        allowed_view = broker.execute(
            operator,
            "android.devices.capabilities",
            {"request_id": "cap-priv-op", "device_id": "dev-priv"},
        )
        self.assertEqual("completed", allowed_view["status"])
        acquired = broker.execute(
            operator,
            "android.sessions.acquire",
            {"request_id": "acq-priv", "device_id": "dev-priv"},
        )
        self.assertEqual("completed", acquired["status"])


if __name__ == "__main__":
    unittest.main()
