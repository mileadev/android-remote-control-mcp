"""Tests for device enrollment, caller registry and lease fencing."""

from __future__ import annotations

import unittest

from station.leases import (
    DeviceBusy,
    GenerationStale,
    LeaseCallerMismatch,
    LeaseDeviceMismatch,
    LeaseError,
    LeaseExpired,
    LeaseTable,
    UnknownLease,
)
from station.registry import (
    CALLER_ROLES,
    Caller,
    CallerRegistry,
    DeviceRegistry,
    OperatorApproval,
    RegistryError,
)

from station.tests.support import (
    DEVICES,
    FakeClock,
    SeqIds,
    enroll_and_make_available,
)

POLL = "interactive"
SCHED = "scheduled"


def _approval_for(
    approval: OperatorApproval, serial: str, pool: str, device_id: str, fingerprint: str
) -> str:
    return approval.sign(serial=serial, pool=pool, device_id=device_id, fingerprint=fingerprint)


class EnrollmentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.approval = OperatorApproval(b"0123456789abcdef")
        self.registry = DeviceRegistry(
            {"emulator-5554": POLL, "emulator-5556": POLL, "R3CTEST00DEVICE": SCHED},
            self.approval,
        )

    def test_serial_must_be_explicit_and_enrolled(self) -> None:
        serial, device_id, fingerprint = DEVICES["pixel"]
        signature = _approval_for(self.approval, serial, POLL, device_id, fingerprint)
        device = self.registry.enroll(
            serial=serial,
            device_id=device_id,
            hardware_fingerprint=fingerprint,
            approval=signature,
        )
        self.assertEqual("NEW", device.state)
        self.assertEqual(device_id, self.registry.get(device_id).device_id)
        self.assertEqual(device_id, self.registry.get_by_serial(serial).device_id)

    def test_enroll_rejects_unallowlisted_serial(self) -> None:
        signature = _approval_for(
            self.approval, "rogue-device-01", POLL, "dev-rogue", "fp"
        )
        with self.assertRaisesRegex(RegistryError, "allowlist"):
            self.registry.enroll(
                serial="rogue-device-01",
                device_id="dev-rogue",
                hardware_fingerprint="fp",
                approval=signature,
            )

    def test_enroll_rejects_invalid_serial_characters(self) -> None:
        with self.assertRaisesRegex(RegistryError, "invalid characters"):
            self.registry.enroll(
                serial="emulato; rm -rf /",
                device_id="dev-x",
                hardware_fingerprint="fp",
                approval=None,
            )

    def test_enroll_requires_valid_operator_approval(self) -> None:
        serial, device_id, fingerprint = DEVICES["pixel"]
        self.registry.enroll(
            serial=serial,
            device_id=device_id,
            hardware_fingerprint=fingerprint,
            approval=_approval_for(self.approval, serial, POLL, device_id, fingerprint),
        )
        bad_serial, bad_id, bad_fp = DEVICES["sched"]
        bad_pool = self.registry.allowlist[bad_serial]
        with self.assertRaisesRegex(RegistryError, "operator approval"):
            self.registry.enroll(
                serial=bad_serial,
                device_id=bad_id,
                hardware_fingerprint=bad_fp,
                approval=_approval_for(
                    self.approval, bad_serial, bad_pool, "dev-other", bad_fp
                ),
            )

    def test_duplicate_device_or_serial_refused(self) -> None:
        serial, device_id, fingerprint = DEVICES["pixel"]
        signature = _approval_for(self.approval, serial, POLL, device_id, fingerprint)
        self.registry.enroll(
            serial=serial,
            device_id=device_id,
            hardware_fingerprint=fingerprint,
            approval=signature,
        )
        with self.assertRaisesRegex(RegistryError, "already enrolled"):
            self.registry.enroll(
                serial=serial,
                device_id="dev-pixel-2",
                hardware_fingerprint=fingerprint,
                approval=_approval_for(
                    self.approval, serial, POLL, "dev-pixel-2", fingerprint
                ),
            )
        with self.assertRaisesRegex(RegistryError, "already enrolled"):
            self.registry.enroll(
                serial=serial,
                device_id=device_id,
                hardware_fingerprint=fingerprint,
                approval=signature,
            )

    def test_auto_selection_is_refused(self) -> None:
        for spec in DEVICES.values():
            enroll_and_make_available(self.registry, self.approval, spec)
        with self.assertRaises(RegistryError):
            self.registry.get(None)
        with self.assertRaises(RegistryError):
            self.registry.get_by_serial(None)
        with self.assertRaises(RegistryError):
            self.registry.get_by_serial("unknown-serial-01")

    def test_happy_path_state_machine(self) -> None:
        device_id = enroll_and_make_available(self.registry, self.approval, DEVICES["pixel"])
        self.assertEqual("AVAILABLE", self.registry.state(device_id))
        self.registry.mark_leased(device_id)
        self.assertEqual("LEASED", self.registry.state(device_id))
        self.registry.mark_released(device_id)
        self.assertEqual("DRAINING", self.registry.state(device_id))
        self.registry.mark_available(device_id)
        self.assertEqual("AVAILABLE", self.registry.state(device_id))

    def test_invalid_transitions_refused(self) -> None:
        serial, device_id, fingerprint = DEVICES["pixel"]
        self.registry.enroll(
            serial=serial,
            device_id=device_id,
            hardware_fingerprint=fingerprint,
            approval=_approval_for(self.approval, serial, POLL, device_id, fingerprint),
        )
        with self.assertRaises(RegistryError):
            self.registry.mark_available(device_id)
        with self.assertRaises(RegistryError):
            self.registry.mark_released(device_id)
        self.registry.verify_device(device_id)
        with self.assertRaises(RegistryError):
            self.registry.mark_leased(device_id)

    def test_quarantine_any_state_and_approval_gated_return(self) -> None:
        device_id = enroll_and_make_available(self.registry, self.approval, DEVICES["pixel"])
        self.registry.quarantine(device_id, "suspected tampering")
        self.assertEqual("QUARANTINED", self.registry.state(device_id))
        with self.assertRaises(RegistryError):
            self.registry.mark_available(device_id)
        with self.assertRaises(RegistryError):
            self.registry.unquarantine(device_id, "v1:not-the-right-code")
        device = self.registry.get(device_id)
        self.registry.unquarantine(
            device_id,
            _approval_for(
                self.approval, device.serial, device.pool, device.device_id,
                device.hardware_fingerprint,
            ),
        )
        self.assertEqual("VERIFIED", self.registry.state(device_id))

    def test_quarantine_requires_reason(self) -> None:
        device_id = enroll_and_make_available(self.registry, self.approval, DEVICES["pixel"])
        with self.assertRaises(RegistryError):
            self.registry.quarantine(device_id, "")
        with self.assertRaises(RegistryError):
            self.registry.quarantine(device_id, "x" * 600)

    def test_operator_approval_key_too_short(self) -> None:
        with self.assertRaises(RegistryError):
            OperatorApproval(b"short")

    def test_caller_validation(self) -> None:
        for role in CALLER_ROLES:
            Caller(identity=f"u-{role}", roles=(role,), device_scope=("dev-pixel",))
        with self.assertRaises(RegistryError):
            Caller(identity="x", roles=("superuser",), device_scope=("dev-pixel",))
        with self.assertRaises(RegistryError):
            Caller(identity="x", roles=("operator",), device_scope=())
        with self.assertRaises(RegistryError):
            Caller(identity="x", roles=("operator",), device_scope=("*",))
        with self.assertRaises(RegistryError):
            Caller(identity="", roles=("operator",), device_scope=("dev-pixel",))

    def test_caller_registry_resolves_only_registered_tokens(self) -> None:
        callers = CallerRegistry()
        caller = Caller(
            identity="alice", roles=("operator",), device_scope=("dev-pixel",)
        )
        callers.register(token="token-abcdefghijklmnop", caller=caller)
        self.assertIsNone(callers.resolve("token-bad"))
        self.assertIsNone(callers.resolve(None))
        self.assertIsNone(callers.resolve(12345))
        resolved = callers.resolve("token-abcdefghijklmnop")
        self.assertEqual("alice", resolved.identity)


class LeaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.table = LeaseTable(ttl_seconds=300, clock=self.clock, id_factory=SeqIds())

    def test_device_lease_is_exclusive_and_fenced(self) -> None:
        first = self.table.acquire("dev-1", "alice")
        self.assertEqual(1, first.generation)
        with self.assertRaises(DeviceBusy):
            self.table.acquire("dev-1", "bob")
        self.assertIsNone(self.table.active_lease("dev-unknown"))
        self.assertEqual(0, self.table.generation("dev-unknown"))

    def test_generation_is_monotonic_never_reused(self) -> None:
        first = self.table.acquire("dev-1", "alice")
        self.table.release(
            device_id="dev-1", lease_id=first.lease_id, caller="alice", generation=1
        )
        second = self.table.acquire("dev-1", "alice")
        self.assertEqual(2, second.generation)
        self.clock.advance(10_000)
        self.table.expire_due()
        third = self.table.acquire("dev-1", "carol")
        self.assertEqual(3, third.generation)

    def test_renew_extends_ttl(self) -> None:
        lease = self.table.acquire("dev-1", "alice")
        renewed = self.table.renew(
            device_id="dev-1", lease_id=lease.lease_id, caller="alice", generation=1
        )
        self.assertEqual(lease.acquired_at + 300, renewed.expires_at)
        self.clock.advance(250)
        second = self.table.renew(
            device_id="dev-1",
            lease_id=lease.lease_id,
            caller="alice",
            generation=1,
        )
        self.assertEqual(1250 + 300, second.expires_at)

    def test_renew_rejects_mismatches(self) -> None:
        lease = self.table.acquire("dev-1", "alice")
        with self.assertRaises(LeaseCallerMismatch):
            self.table.renew(
                device_id="dev-1", lease_id=lease.lease_id, caller="bob", generation=1
            )
        with self.assertRaises(GenerationStale):
            self.table.renew(
                device_id="dev-1", lease_id=lease.lease_id, caller="alice", generation=99
            )
        with self.assertRaises(LeaseDeviceMismatch):
            self.table.renew(
                device_id="dev-2", lease_id=lease.lease_id, caller="alice", generation=1
            )
        with self.assertRaises(UnknownLease):
            self.table.renew(
                device_id="dev-1", lease_id="lease-9999", caller="alice", generation=1
            )

    def test_validate_rejects_stale_generation(self) -> None:
        lease = self.table.acquire("dev-1", "alice")
        with self.assertRaises(GenerationStale):
            self.table.validate(
                device_id="dev-1", lease_id=lease.lease_id, caller="alice", generation=5
            )
        self.table.validate(
            device_id="dev-1", lease_id=lease.lease_id, caller="alice", generation=1
        )

    def test_expiry_is_detected_by_validate_and_expire_due(self) -> None:
        lease = self.table.acquire("dev-1", "alice")
        self.clock.advance(299)
        self.table.validate(
            device_id="dev-1", lease_id=lease.lease_id, caller="alice", generation=1
        )
        self.clock.advance(2)
        with self.assertRaises(LeaseExpired):
            self.table.validate(
                device_id="dev-1", lease_id=lease.lease_id, caller="alice", generation=1
            )
        expired = self.table.expire_due()
        self.assertEqual((lease.lease_id,), tuple(l.lease_id for l in expired))
        self.assertEqual((), self.table.expire_due())

    def test_release_clears_and_tolerates_expired_release(self) -> None:
        lease = self.table.acquire("dev-1", "alice")
        released = self.table.release(
            device_id="dev-1", lease_id=lease.lease_id, caller="alice", generation=1
        )
        self.assertEqual(lease, released)
        self.assertIsNone(self.table.active_lease("dev-1"))
        with self.assertRaises(UnknownLease):
            self.table.release(
                device_id="dev-1", lease_id=lease.lease_id, caller="alice", generation=1
            )
        self.clock.advance(5_000)
        expired = self.table.acquire("dev-1", "bob")
        self.clock.advance(301)
        self.assertIsNone(
            self.table.release(
                device_id="dev-1", lease_id=expired.lease_id, caller="bob", generation=2
            )
        )

    def test_snapshot_lists_active_only(self) -> None:
        self.table.acquire("dev-1", "alice")
        lease2 = self.table.acquire("dev-2", "bob")
        self.assertEqual(2, len(self.table.snapshot()))
        self.table.release(
            device_id="dev-2", lease_id=lease2.lease_id, caller="bob", generation=1
        )
        self.assertEqual(1, len(self.table.snapshot()))

    def test_id_collision_guard(self) -> None:
        table = LeaseTable(ttl_seconds=300, clock=self.clock, id_factory=lambda: "dup-1")
        table.acquire("dev-1", "alice")
        table.release(
            device_id="dev-1", lease_id="dup-1", caller="alice", generation=1
        )
        table.acquire("dev-1", "bob")
        with self.assertRaises(LeaseError):
            table.acquire("dev-2", "carol")


if __name__ == "__main__":
    unittest.main()
