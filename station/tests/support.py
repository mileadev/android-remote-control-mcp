"""Shared fixtures for the station test suite (deterministic, no I/O)."""

from __future__ import annotations

import unittest
from pathlib import Path

from station.adb_access import AdbCommandPolicy
from station.broker import BrokerStation
from station.drivers import RecordingDeviceDriver
from station.lab_policy import LabPolicy, load_lab_policy_file
from station.leases import LeaseTable
from station.registry import Caller, CallerRegistry, DeviceRegistry, OperatorApproval

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "lab-policy.example.yaml"
DEFAULT_TOKEN = "labtoken-0123456789abcdef"
SECOND_TOKEN = "labtoken-fedcba9876543210"


def load_default_policy() -> LabPolicy:
    return load_lab_policy_file(POLICY_PATH)


def mutate_policy(base: str, replacements: dict[str, str]) -> str:
    text = base
    for old, new in replacements.items():
        if old not in text:
            raise AssertionError(f"fixture mutation target missing: {old!r}")
        text = text.replace(old, new, 1)
    return text


class FakeClock:
    """Deterministic monotonic clock."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class SeqIds:
    """Deterministic lease id factory."""

    def __init__(self, prefix: str = "lease") -> None:
        self._prefix = prefix
        self._n = 0

    def __call__(self) -> str:
        self._n += 1
        return f"{self._prefix}-{self._n:04d}"


UTC = lambda: "2026-01-15T00:00:00Z"


def build_registry(
    allowlist: dict[str, str] | None = None,
) -> tuple[DeviceRegistry, OperatorApproval]:
    approval = OperatorApproval(b"0123456789abcdef")
    if allowlist is None:
        allowlist = {
            "emulator-5554": "interactive",
            "emulator-5556": "interactive",
            "R3CTEST00DEVICE": "scheduled",
        }
    return DeviceRegistry(allowlist, approval), approval


def make_caller(
    identity: str,
    roles: tuple[str, ...],
    scope: tuple[str, ...],
) -> Caller:
    return Caller(identity=identity, roles=roles, device_scope=scope)


def build_broker(
    clock: FakeClock,
    *,
    policy: LabPolicy | None = None,
    registry: DeviceRegistry | None = None,
    driver: RecordingDeviceDriver | None = None,
    ttl_seconds: int = 900,
    preapproved_tests: frozenset[str] = frozenset(),
    adb_runner=None,
    leasing: LeaseTable | None = None,
    catalog: dict | None = None,
    attested_tier_ceiling: str | None = None,
) -> tuple[BrokerStation, LeaseTable]:
    if policy is None:
        policy = load_default_policy()
    if registry is None:
        registry, _ = build_registry()
    if driver is None:
        driver = RecordingDeviceDriver()
    if leasing is None:
        leasing = LeaseTable(
            ttl_seconds=ttl_seconds, clock=clock, id_factory=SeqIds()
        )
    broker = BrokerStation(
        policy=policy,
        registry=registry,
        leasing=leasing,
        driver=driver,
        adb_policy=AdbCommandPolicy(registry),
        adb_runner=adb_runner or (lambda argv, timeout: (0, "", "")),
        clock=clock,
        utc_now=UTC,
        preapproved_tests=preapproved_tests,
        catalog=catalog,
        attested_tier_ceiling=attested_tier_ceiling or "T2_TEST",
    )
    return broker, leasing


class StationTestCase(unittest.TestCase):
    """Base case wiring a deterministic broker fixture."""

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.registry, self.approval = build_registry()
        self.driver = RecordingDeviceDriver()
        self.broker, self.leasing = build_broker(
            self.clock, registry=self.registry, driver=self.driver
        )
        self.callers = CallerRegistry()
        self.alice = make_caller(
            "alice", ("operator", "observer"), ("dev-pixel", "dev-second")
        )
        self.bob = make_caller("bob", ("observer",), ("dev-pixel", "dev-second"))
        self.ci = make_caller("ci-bot", ("test-runner",), ("dev-second",))
        self.callers.register(token=DEFAULT_TOKEN, caller=self.alice)
        self.callers.register(token=SECOND_TOKEN, caller=self.bob)


def enroll_and_make_available(registry: DeviceRegistry, approval: OperatorApproval, spec: tuple[str, str, str]) -> str:
    serial, device_id, fingerprint = spec
    pool = registry.allowlist[serial] if serial in registry.allowlist else "interactive"
    signature = approval.sign(
        serial=serial, pool=pool, device_id=device_id, fingerprint=fingerprint
    )
    registry.enroll(
        serial=serial,
        device_id=device_id,
        hardware_fingerprint=fingerprint,
        approval=signature,
    )
    registry.verify_device(device_id)
    registry.mark_available(device_id)
    return device_id


DEVICES = {
    "pixel": ("emulator-5554", "dev-pixel", "fp-pixel-a"),
    "second": ("emulator-5556", "dev-second", "fp-second-b"),
    "sched": ("R3CTEST00DEVICE", "dev-sched", "fp-sched-c"),
}