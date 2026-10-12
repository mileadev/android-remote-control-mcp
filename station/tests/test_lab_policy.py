"""Tests for the fail-closed lab policy parser and invariants."""

from __future__ import annotations

import unittest

from station.lab_policy import PolicyError, load_lab_policy, load_lab_policy_file

from station.tests.support import POLICY_PATH, mutate_policy

BASE = POLICY_PATH.read_text(encoding="utf-8")


class LabPolicyTest(unittest.TestCase):
    def test_parses_default_example_config(self) -> None:
        policy = load_lab_policy_file(POLICY_PATH)
        self.assertEqual("station-policy-1", policy.schema_version)
        self.assertEqual("deny_by_default", policy.mode)
        self.assertFalse(policy.control_plane.expose_public_http)
        self.assertEqual("mtls_private", policy.control_plane.transport)
        self.assertEqual(900, policy.session.lease_ttl_seconds)
        self.assertEqual(60, policy.session.heartbeat_seconds)
        self.assertEqual(300, policy.session.idempotency_ttl_seconds)
        self.assertTrue(policy.session.exclusive_device_lease)
        self.assertTrue(policy.session.require_station_fencing_generation)
        self.assertTrue(policy.session.deny_on_backend_unavailable)
        self.assertTrue(policy.device_enrollment.explicit_serial_allowlist)
        self.assertFalse(policy.device_enrollment.allow_mdns_autoconnect)
        self.assertEqual(12, len(policy.station.allowed_operations))
        for op in (
            "android.devices.list",
            "android.sessions.acquire",
            "android.ui.batch",
            "android.api.invoke_typed",
            "android.tests.submit",
        ):
            self.assertIn(op, policy.station.allowed_operations)
        self.assertIn("raw_adb_shell", policy.station.never_expose_to_llm)
        self.assertIn("android.video.session", policy.station.never_expose_to_llm)
        self.assertIn("android.logs.query", policy.station.never_expose_to_llm)
        self.assertTrue(policy.station.release_on_lease_expiry)
        self.assertTrue(policy.station.reject_ats_owned_devices)
        self.assertFalse(policy.logging.log_payloads)
        self.assertTrue(policy.logging.record_request_id)
        self.assertTrue(policy.privileged_pool.requires_operator_approval)

    def test_digest_is_deterministic(self) -> None:
        first = load_lab_policy_file(POLICY_PATH)
        second = load_lab_policy_file(POLICY_PATH)
        self.assertEqual(first.config_digest, second.config_digest)
        self.assertTrue(first.config_digest.startswith("sha256:"))

    def test_disallows_public_http(self) -> None:
        with self.assertRaisesRegex(PolicyError, "expose_public_http"):
            load_lab_policy(mutate_policy(BASE, {"expose_public_http: false": "expose_public_http: true"}))

    def test_requires_private_transport(self) -> None:
        with self.assertRaisesRegex(PolicyError, "transport"):
            load_lab_policy(mutate_policy(BASE, {"mtls_private": "https_public"}))

    def test_requires_oidc_identity(self) -> None:
        with self.assertRaisesRegex(PolicyError, "require_oidc_identity"):
            load_lab_policy(mutate_policy(BASE, {"require_oidc_identity: true": "require_oidc_identity: false"}))

    def test_rejects_unknown_schema_version(self) -> None:
        with self.assertRaisesRegex(PolicyError, "schema_version"):
            load_lab_policy(
                mutate_policy(BASE, {"schema_version: station-policy-1": "schema_version: proposal-1"})
            )

    def test_rejects_wrong_mode(self) -> None:
        with self.assertRaisesRegex(PolicyError, "mode"):
            load_lab_policy(mutate_policy(BASE, {"deny_by_default": "allow_by_default"}))

    def test_rejects_lease_ttl_out_of_range(self) -> None:
        with self.assertRaisesRegex(PolicyError, "lease_ttl_seconds"):
            load_lab_policy(mutate_policy(BASE, {"lease_ttl_seconds: 900": "lease_ttl_seconds: 5"}))

    def test_rejects_heartbeat_above_ttl(self) -> None:
        with self.assertRaisesRegex(PolicyError, "heartbeat_seconds"):
            load_lab_policy(mutate_policy(BASE, {"heartbeat_seconds: 60": "heartbeat_seconds: 9000"}))

    def test_rejects_idempotency_ttl_out_of_range(self) -> None:
        with self.assertRaisesRegex(PolicyError, "idempotency_ttl_seconds"):
            load_lab_policy(mutate_policy(BASE, {"idempotency_ttl_seconds: 300": "idempotency_ttl_seconds: 2"}))

    def test_rejects_implicit_serial_allowlist(self) -> None:
        with self.assertRaisesRegex(PolicyError, "explicit_serial_allowlist"):
            load_lab_policy(mutate_policy(BASE, {"explicit_serial_allowlist: true": "explicit_serial_allowlist: false"}))

    def test_rejects_mdns_discovery(self) -> None:
        with self.assertRaisesRegex(PolicyError, "allow_mdns_autoconnect"):
            load_lab_policy(mutate_policy(BASE, {"allow_mdns_autoconnect: false": "allow_mdns_autoconnect: true"}))

    def test_rejects_public_adb_tcp(self) -> None:
        with self.assertRaisesRegex(PolicyError, "allow_adb_tcp_public"):
            load_lab_policy(mutate_policy(BASE, {"allow_adb_tcp_public: false": "allow_adb_tcp_public: true"}))

    def test_rejects_root_on_stock_devices(self) -> None:
        with self.assertRaisesRegex(PolicyError, "allow_root_on_stock_devices"):
            load_lab_policy(mutate_policy(BASE, {"allow_root_on_stock_devices: false": "allow_root_on_stock_devices: true"}))

    def test_rejects_non_loopback_native_bind(self) -> None:
        with self.assertRaisesRegex(PolicyError, "device_bind_address"):
            load_lab_policy(mutate_policy(BASE, {'device_bind_address: "127.0.0.1"': 'device_bind_address: "0.0.0.0"'}))

    def test_rejects_forbidden_native_port(self) -> None:
        with self.assertRaisesRegex(PolicyError, "device_port"):
            load_lab_policy(mutate_policy(BASE, {"device_port: 8765": "device_port: 5037"}))

    def test_rejects_dual_auth_disabled(self) -> None:
        with self.assertRaisesRegex(PolicyError, "allow_dual_auth_disabled"):
            load_lab_policy(mutate_policy(BASE, {"allow_dual_auth_disabled: false": "allow_dual_auth_disabled: true"}))

    def test_rejects_any_origin(self) -> None:
        with self.assertRaisesRegex(PolicyError, "allow_any_origin"):
            load_lab_policy(mutate_policy(BASE, {"allow_any_origin: false": "allow_any_origin: true"}))

    def test_rejects_disabled_auth(self) -> None:
        with self.assertRaisesRegex(PolicyError, "require_auth"):
            load_lab_policy(mutate_policy(BASE, {"require_auth: true": "require_auth: false"}))

    def test_rejects_public_tunnels(self) -> None:
        with self.assertRaisesRegex(PolicyError, "enable_public_tunnels"):
            load_lab_policy(mutate_policy(BASE, {"enable_public_tunnels: false": "enable_public_tunnels: true"}))

    def test_rejects_http_download(self) -> None:
        with self.assertRaisesRegex(PolicyError, "enable_http_download"):
            load_lab_policy(mutate_policy(BASE, {"enable_http_download: false": "enable_http_download: true"}))

    def test_rejects_unverified_certs(self) -> None:
        with self.assertRaisesRegex(PolicyError, "allow_unverified_https_certs"):
            load_lab_policy(mutate_policy(BASE, {"allow_unverified_https_certs: false": "allow_unverified_https_certs: true"}))

    def test_rejects_unknown_operation_in_allowlist(self) -> None:
        with self.assertRaisesRegex(PolicyError, "known operation"):
            load_lab_policy(
                mutate_policy(
                    BASE,
                    {"- android.devices.list": "- android.devices.list\n    - android.pagerage.inject"},
                )
            )

    def test_rejects_missing_mandatory_forbidden_entry(self) -> None:
        with self.assertRaisesRegex(PolicyError, "raw_adb_shell"):
            load_lab_policy(mutate_policy(BASE, {"    - raw_adb_shell\n": ""}))

    def test_rejects_overlap_between_allowed_and_forbidden(self) -> None:
        with self.assertRaisesRegex(PolicyError, "must not be in never_expose"):
            load_lab_policy(
                mutate_policy(
                    BASE,
                    {"    - android.ui.batch\n": "    - android.ui.batch\n    - android.video.session\n"},
                )
            )

    def test_rejects_bad_tool_id_pattern(self) -> None:
        with self.assertRaisesRegex(PolicyError, "allowed_tool_ids"):
            load_lab_policy(mutate_policy(BASE, {"- android_ui_observe": "- Android-UI"}))

    def test_rejects_logging_payload_capture(self) -> None:
        with self.assertRaisesRegex(PolicyError, "log_payloads"):
            load_lab_policy(mutate_policy(BASE, {"log_payloads: false": "log_payloads: true"}))

    def test_rejects_privileged_pool_without_approval(self) -> None:
        with self.assertRaisesRegex(PolicyError, "requires_operator_approval"):
            load_lab_policy(
                mutate_policy(BASE, {"requires_operator_approval: true": "requires_operator_approval: false"})
            )

    def test_rejects_tabs(self) -> None:
        with self.assertRaisesRegex(PolicyError, "tab"):
            load_lab_policy("schema_version: station-policy-1\nmode:\tdeny_by_default\n")

    def test_rejects_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(PolicyError, "duplicate"):
            load_lab_policy(
                mutate_policy(BASE, {"  expose_public_http: false": "  expose_public_http: false\n  expose_public_http: true"})
            )

    def test_rejects_unknown_section(self) -> None:
        with self.assertRaisesRegex(PolicyError, "unknown key|top-level"):
            load_lab_policy(
                mutate_policy(BASE, {"mode: deny_by_default\n": "mode: deny_by_default\nextra_section:\n  a: 1\n"})
            )

    def test_rejects_empty_document(self) -> None:
        with self.assertRaisesRegex(PolicyError, "empty"):
            load_lab_policy("")
            load_lab_policy("# only a comment\n")

    def test_rejects_non_integer_port(self) -> None:
        with self.assertRaisesRegex(PolicyError, "device_port"):
            load_lab_policy(mutate_policy(BASE, {"device_port: 8765": 'device_port: "8765"'}))

    def test_rejects_odd_indentation(self) -> None:
        with self.assertRaisesRegex(PolicyError, "indent"):
            load_lab_policy(
                mutate_policy(BASE, {"  expose_public_http: false": "   expose_public_http: false"})
            )


if __name__ == "__main__":
    unittest.main()