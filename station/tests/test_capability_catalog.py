"""Tests for the H-12 capability catalog: validation, attestation, broker + HTTP."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import threading
import unittest
import urllib.error
import urllib.request

from station.capability_catalog import (
    CAPABILITY_ENTRY_KEYS,
    CapabilityCatalogError,
    PRIVILEGE_TIERS,
    STATION_REFERENCE_CATALOG,
    attest_device,
    attest_device_catalog,
    canonical_revision,
    tier_rank,
    validate_catalog,
    validate_entry,
)
from station.http_api import StationControlPlane
from station.registry import CallerRegistry
from station.tests.support import (
    DEFAULT_TOKEN,
    DEVICES,
    FakeClock,
    SECOND_TOKEN,
    StationTestCase,
    build_broker,
    build_registry,
    enroll_and_make_available,
    load_default_policy,
    make_caller,
)


def make_entry(
    api_id: str = "android.probe.sample.v1",
    *,
    tier: str = "T1_APP",
    risk: str = "read_only",
    permissions: list[str] | None = None,
    hardware: list[str] | None = None,
) -> dict:
    return {
        "api_id": api_id,
        "adapter_id": "probe_adapter_v1",
        "platform": "android",
        "min_api_level": 33,
        "max_api_level": None,
        "privilege_tier": tier,
        "required_permissions": permissions if permissions is not None else [],
        "hardware_features": hardware if hardware is not None else [],
        "argument_schema_revision": "1",
        "risk": risk,
        "device_status": "not_tested",
        "verification": {"test_id": None, "apk_sha256": None, "timestamp_utc": None},
    }


class CapabilityCatalogValidationTest(unittest.TestCase):
    def test_reference_entry_passes_validation(self) -> None:
        entry = STATION_REFERENCE_CATALOG["android.wifi.read_connection_info.v1"]
        self.assertIs(entry, validate_entry("android.wifi.read_connection_info.v1", entry))
        self.assertIs(STATION_REFERENCE_CATALOG, validate_catalog(STATION_REFERENCE_CATALOG))

    def test_key_set_mismatch_is_fail_closed(self) -> None:
        entry = make_entry()
        missing = {k: v for k, v in entry.items() if k != "risk"}
        for broken in (missing, {**entry, "extra_key": "x"}):
            with self.assertRaises(CapabilityCatalogError) as ctx:
                validate_entry("android.probe.sample.v1", broken)
            self.assertIn("key set mismatch", str(ctx.exception))

    def test_entry_api_id_disagreement_is_fail_closed(self) -> None:
        entry = make_entry(api_id="android.probe.other.v1")
        with self.assertRaisesRegex(CapabilityCatalogError, "disagrees with entry api_id"):
            validate_entry("android.probe.sample.v1", entry)

    def test_malformed_field_values_are_fail_closed(self) -> None:
        broken_values = [
            ("adapter_id", "Probe_Adapter"),
            ("adapter_id", "ab"),
            ("platform", "linux"),
            ("privilege_tier", "T6_FUTURE"),
            ("risk", "sparkly"),
            ("device_status", "maybe"),
            ("min_api_level", 0),
            ("min_api_level", True),
            ("min_api_level", "33"),
            ("max_api_level", 32),
            ("max_api_level", "33"),
            ("required_permissions", ["android.permission.camera"]),
            ("required_permissions", {"android.permission.CAMERA"}),
            ("hardware_features", ["android.sensor.camera"]),
            ("hardware_features", "android.hardware.camera"),
            ("argument_schema_revision", "UPPER"),
            ("argument_schema_revision", ""),
            ("adapter_id", 7),
            ("verification", []),
        ]
        for key, value in broken_values:
            with self.subTest(key=key, value=value):
                entry = dict(make_entry())
                entry[key] = value
                with self.assertRaises(CapabilityCatalogError):
                    validate_entry("android.probe.sample.v1", entry)

    def test_min_api_level_below_floor_is_rejected(self) -> None:
        entry = dict(make_entry())
        entry["min_api_level"] = 32
        with self.assertRaisesRegex(CapabilityCatalogError, "MIN_APP_API_LEVEL"):
            validate_entry("android.probe.sample.v1", entry)

    def test_verified_status_requires_full_evidence(self) -> None:
        entry = dict(make_entry())
        entry["device_status"] = "verified"
        with self.assertRaisesRegex(CapabilityCatalogError, "requires full test evidence"):
            validate_entry("android.probe.sample.v1", entry)
        filled = dict(entry)
        filled["verification"] = {
            "test_id": "CapabilityCatalogValidationTest",
            "apk_sha256": "sha256:abc",
            "timestamp_utc": "2026-02-15T00:00:00Z",
        }
        self.assertIs(filled, validate_entry("android.probe.sample.v1", filled))

    def test_untested_status_must_not_carry_evidence(self) -> None:
        entry = dict(make_entry())
        entry["verification"] = {
            "test_id": "CapabilityCatalogValidationTest",
            "apk_sha256": None,
            "timestamp_utc": None,
        }
        with self.assertRaisesRegex(CapabilityCatalogError, "must not carry test evidence"):
            validate_entry("android.probe.sample.v1", entry)

    def test_every_contract_key_is_enforced(self) -> None:
        self.assertEqual(12, len(CAPABILITY_ENTRY_KEYS))
        self.assertEqual(set(make_entry().keys()), set(CAPABILITY_ENTRY_KEYS))

    def test_tier_rank_is_contract_ordered(self) -> None:
        for index, tier in enumerate(PRIVILEGE_TIERS, start=1):
            self.assertEqual(index, tier_rank(tier))
        with self.assertRaises(CapabilityCatalogError):
            tier_rank("T9_OMEGA")

    def test_canonical_revision_matches_independent_computation(self) -> None:
        catalog = {"a.v1": make_entry("a.v1"), "b.v1": make_entry("b.v1", tier="T3_MANAGED")}
        expected = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        )
        self.assertEqual(expected, canonical_revision(catalog))
        self.assertEqual(canonical_revision(catalog), canonical_revision(dict(reversed(list(catalog.items())))))
        other = {"a.v1": make_entry("a.v1")}
        self.assertNotEqual(canonical_revision(catalog), canonical_revision(other))


class CapabilityCatalogAttestationTest(unittest.TestCase):
    def test_identical_catalog_attests(self) -> None:
        reference = {"android.probe.sample.v1": make_entry()}
        violations, drift = attest_device_catalog(
            dict(reference), reference_catalog=reference, tier_ceiling="T2_TEST"
        )
        self.assertEqual([], violations)
        self.assertEqual([], drift)
        result = attest_device(
            dict(reference),
            device_catalog_revision=None,
            reference_catalog=reference,
            tier_ceiling="T2_TEST",
            catalog_revision="sha256:station",
        )
        self.assertTrue(result["attested"])
        self.assertEqual([], result["violations"])
        self.assertEqual([], result["drift"])
        self.assertEqual("sha256:station", result["catalog_revision"])
        self.assertEqual(canonical_revision(reference), result["device_catalog_revision"])

    def test_unlisted_capability_is_a_violation(self) -> None:
        reference = {"android.probe.sample.v1": make_entry()}
        device = {
            "android.probe.sample.v1": make_entry(),
            "android.probe.rogue.v1": make_entry("android.probe.rogue.v1"),
        }
        result = self._attest(device, reference)
        self.assertFalse(result["attested"])
        self.assertEqual(
            ["android.probe.rogue.v1 is not listed in the station reference catalog"],
            result["violations"],
        )
        self.assertEqual([], result["drift"])

    def test_tier_above_ceiling_is_a_violation(self) -> None:
        reference = {"android.probe.sample.v1": make_entry(tier="T1_APP")}
        device = {"android.probe.sample.v1": make_entry(tier="T3_MANAGED")}
        result = self._attest(device, reference, ceiling="T2_TEST")
        self.assertFalse(result["attested"])
        self.assertIn(
            "android.probe.sample.v1 privilege_tier T3_MANAGED exceeds the station "
            "ceiling T2_TEST",
            result["violations"],
        )
        self.assertEqual([], result["drift"])

    def test_ceiling_upgrade_admits_higher_tier(self) -> None:
        entry = make_entry(tier="T3_MANAGED", risk="mutating")
        reference = {"android.probe.sample.v1": entry}
        with_ceiling = attest_device_catalog(
            dict(reference), reference_catalog=reference, tier_ceiling="T3_MANAGED"
        )
        self.assertEqual(([], []), with_ceiling)
        result = self._attest(dict(reference), reference, ceiling="T2_TEST")
        self.assertFalse(result["attested"])
        self.assertEqual(1, len(result["violations"]))

    def test_field_drift_is_reported_not_violation(self) -> None:
        reference = {"android.probe.sample.v1": make_entry()}
        drifted = make_entry(risk="mutating")
        device = {"android.probe.sample.v1": drifted}
        result = self._attest(device, reference)
        self.assertFalse(result["attested"])
        self.assertEqual([], result["violations"])
        self.assertEqual(
            ["android.probe.sample.v1 differs from the station reference catalog"],
            result["drift"],
        )

    def test_missing_reference_entry_is_drift(self) -> None:
        reference = {
            "android.probe.sample.v1": make_entry(),
            "android.probe.gone.v1": make_entry("android.probe.gone.v1"),
        }
        device = {"android.probe.sample.v1": make_entry()}
        result = self._attest(device, reference)
        self.assertFalse(result["attested"])
        self.assertEqual([], result["violations"])
        self.assertEqual(
            ["android.probe.gone.v1 is missing from the device catalog"], result["drift"]
        )

    def test_declared_revision_mismatch_fails_closed(self) -> None:
        reference = {"android.probe.sample.v1": make_entry()}
        canonical = canonical_revision(reference)
        result = attest_device(
            dict(reference),
            device_catalog_revision=canonical,
            reference_catalog=reference,
            tier_ceiling="T2_TEST",
            catalog_revision="sha256:station",
        )
        self.assertTrue(result["attested"])
        with self.assertRaisesRegex(CapabilityCatalogError, "device_catalog_revision mismatch"):
            attest_device(
                dict(reference),
                device_catalog_revision="sha256:" + "0" * 64,
                reference_catalog=reference,
                tier_ceiling="T2_TEST",
                catalog_revision="sha256:station",
            )
        with self.assertRaisesRegex(CapabilityCatalogError, "must be a string or null"):
            attest_device(
                dict(reference),
                device_catalog_revision=42,
                reference_catalog=reference,
                tier_ceiling="T2_TEST",
                catalog_revision="sha256:station",
            )

    def test_invalid_catalog_fails_closed(self) -> None:
        reference = {"android.probe.sample.v1": make_entry()}
        broken = {"android.probe.sample.v1": {k: v for k, v in make_entry().items() if k != "risk"}}
        for bad in (broken, {**reference, "not-an-operation-id": make_entry("x")}):
            with self.assertRaises(CapabilityCatalogError):
                attest_device_catalog(
                    dict(bad), reference_catalog=reference, tier_ceiling="T2_TEST"
                )
        with self.assertRaisesRegex(CapabilityCatalogError, "unknown privilege tier"):
            attest_device(
                dict(reference),
                device_catalog_revision=None,
                reference_catalog=reference,
                tier_ceiling="T9_OMEGA",
                catalog_revision="sha256:station",
            )

    def _attest(
        self,
        device: dict,
        reference: dict,
        *,
        ceiling: str = "T2_TEST",
    ) -> dict:
        return attest_device(
            dict(device),
            device_catalog_revision=None,
            reference_catalog=reference,
            tier_ceiling=ceiling,
            catalog_revision="sha256:station",
        )


class CapabilityCatalogBrokerTest(StationTestCase):
    """Broker-level attest operation tests (identity/scope enforced by the station)."""

    def setUp(self) -> None:
        super().setUp()
        base = load_default_policy()
        self.policy_without_attest = base
        self.policy_with_attest = dataclasses.replace(
            base,
            station=dataclasses.replace(
                base.station,
                allowed_operations=base.station.allowed_operations
                + ("android.devices.attest",),
            ),
        )
        enroll_and_make_available(self.registry, self.approval, DEVICES["pixel"])
        self.broker, self.leasing = build_broker(self.clock, registry=self.registry, driver=self.driver)

    def _attest_envelope(self, catalog: dict, request_id: str = "req-attest") -> dict:
        return {
            "request_id": request_id,
            "device_id": "dev-pixel",
            "arguments": {"catalog": catalog},
        }

    def test_attest_operation_denied_without_explicit_policy(self) -> None:
        response = self.broker.execute(
            self.bob,
            "android.devices.attest",
            self._attest_envelope(STATION_REFERENCE_CATALOG),
        )
        self.assertEqual("denied", response["status"])
        self.assertIn("station policy", response["error"])

    def test_attest_matches_reference_catalog(self) -> None:
        attesting, _ = build_broker(
            self.clock, registry=self.registry, driver=self.driver, policy=self.policy_with_attest
        )
        response = attesting.execute(
            self.bob,
            "android.devices.attest",
            self._attest_envelope(dict(STATION_REFERENCE_CATALOG)),
        )
        self.assertEqual("completed", response["status"], response)
        self.assertTrue(response["result"]["attested"])
        self.assertEqual([], response["result"]["violations"])
        self.assertEqual([], response["result"]["drift"])
        self.assertEqual(attesting.catalog_revision, response["result"]["catalog_revision"])
        self.assertEqual(
            canonical_revision(STATION_REFERENCE_CATALOG),
            response["result"]["device_catalog_revision"],
        )

    def test_attest_reports_unknown_capability_and_wrong_revision(self) -> None:
        attesting, _ = build_broker(
            self.clock, registry=self.registry, driver=self.driver, policy=self.policy_with_attest
        )
        rogue_catalog = {"android.probe.rogue.v1": make_entry("android.probe.rogue.v1")}
        response = attesting.execute(
            self.bob,
            "android.devices.attest",
            self._attest_envelope(dict(rogue_catalog), request_id="req-attest-2"),
        )
        self.assertEqual("completed", response["status"])
        self.assertFalse(response["result"]["attested"])
        self.assertEqual(1, len(response["result"]["violations"]))
        self.assertIn("not listed in the station reference catalog", response["result"]["violations"][0])
        envelope = self._attest_envelope(dict(STATION_REFERENCE_CATALOG))
        envelope["arguments"]["device_catalog_revision"] = "sha256:" + "0" * 64
        response = attesting.execute(self.bob, "android.devices.attest", envelope)
        self.assertEqual("failed", response["status"])
        self.assertIn("capability catalog is invalid", response["error"])

    def test_attest_requires_broker_catalog_object(self) -> None:
        attesting, _ = build_broker(
            self.clock, registry=self.registry, driver=self.driver, policy=self.policy_with_attest
        )
        response = attesting.execute(
            self.bob,
            "android.devices.attest",
            {"request_id": "req-attest-bad", "device_id": "dev-pixel", "arguments": {}},
        )
        self.assertEqual("failed", response["status"])
        self.assertIn("requires a 'catalog' object", response["error"])

    def test_attest_enforces_device_scope_and_role(self) -> None:
        attesting, _ = build_broker(
            self.clock, registry=self.registry, driver=self.driver, policy=self.policy_with_attest
        )
        enroll_and_make_available(self.registry, self.approval, DEVICES["second"])
        unscoped = make_caller("mallory", ("observer",), ("dev-sched",))
        out_of_scope = attesting.execute(
            unscoped,
            "android.devices.attest",
            {"request_id": "req-attest-scope", "device_id": "dev-second", "arguments": {"catalog": {}}},
        )
        wrong_role = attesting.execute(
            self.ci,
            "android.devices.attest",
            self._attest_envelope(dict(STATION_REFERENCE_CATALOG)),
        )
        self.assertEqual("denied", out_of_scope["status"])
        self.assertIn("not scoped", out_of_scope["error"])
        self.assertEqual("denied", wrong_role["status"])
        self.assertIn("requires role 'observer'", wrong_role["error"])

    def test_catalog_argument_shape_is_validated_fail_closed(self) -> None:
        attesting, _ = build_broker(
            self.clock, registry=self.registry, driver=self.driver, policy=self.policy_with_attest
        )
        invalid = {"android.wifi.read_connection_info.v1": {}}
        response = attesting.execute(
            self.bob,
            "android.devices.attest",
            self._attest_envelope(dict(invalid)),
        )
        self.assertEqual("failed", response["status"])
        self.assertIn("capability catalog is invalid", response["error"])


class CapabilityCatalogHttpTest(unittest.TestCase):
    """Loopback HTTP surface for android.devices.attest."""

    def setUp(self) -> None:
        self.clock = FakeClock()
        registry, approval = build_registry()
        for spec in DEVICES.values():
            enroll_and_make_available(registry, approval, spec)
        base_policy = load_default_policy()
        policy_with_attest = dataclasses.replace(
            base_policy,
            station=dataclasses.replace(
                base_policy.station,
                allowed_operations=base_policy.station.allowed_operations
                + ("android.devices.attest",),
            ),
        )
        broker, self.leasing = build_broker(self.clock, registry=registry, policy=policy_with_attest)
        alice = make_caller("alice", ("operator", "observer"), ("dev-pixel", "dev-second"))
        bob = make_caller("bob", ("observer",), ("dev-pixel",))
        self.callers = CallerRegistry()
        self.callers.register(token=DEFAULT_TOKEN, caller=alice)
        self.callers.register(token=SECOND_TOKEN, caller=bob)
        self.control = StationControlPlane(broker, caller_registry=self.callers)
        self._thread = threading.Thread(target=self.control.start, daemon=True)
        self._thread.start()
        self.base = f"http://{self.control.host}:{self.control.port}"

    def tearDown(self) -> None:
        self.control.stop()
        self._thread.join(timeout=5)

    def _post(self, operation: str, body: dict, *, token: str | None = DEFAULT_TOKEN):
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            f"{self.base}/v1/{operation}",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as ex:
            return ex.code, json.loads(ex.read())

    def test_attest_over_loopback_http(self) -> None:
        status, body = self._post(
            "android.devices.attest",
            {
                "request_id": "http-attest",
                "device_id": "dev-pixel",
                "arguments": {"catalog": dict(STATION_REFERENCE_CATALOG)},
            },
            token=DEFAULT_TOKEN,
        )
        self.assertEqual(200, status, body)
        self.assertEqual("completed", body["status"])
        self.assertTrue(body["result"]["attested"])
        self.assertEqual([], body["result"]["violations"])
        self.assertEqual([], body["result"]["drift"])
        self.assertIn("catalog_revision", body["result"])
        self.assertIn("device_catalog_revision", body["result"])

    def test_attest_requires_authorized_identity(self) -> None:
        status, body = self._post(
            "android.devices.attest",
            {"request_id": "http-attest-401", "device_id": "dev-pixel"},
            token=None,
        )
        self.assertEqual(401, status)
        self.assertIn("identity", body["error"])




if __name__ == "__main__":
    unittest.main()