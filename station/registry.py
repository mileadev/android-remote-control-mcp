"""Device enrollment registry and caller identity registry.

Devices only become usable after being enrolled from an explicit serial
allowlist with a valid operator approval (HMAC-SHA256 over the enrollment
payload). Serial auto-selection, mDNS-style discovery and non-allowlisted
serials are refused by construction.

Device lifecycle (per the lab runbook):
``NEW -> VERIFIED -> AVAILABLE -> LEASED -> DRAINING -> AVAILABLE`` and any
state -> ``QUARANTINED`` (operator-gated return).
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Mapping

SERIAL_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
DEVICE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
POOLS = ("interactive", "scheduled", "privileged")
CALLER_ROLES = ("observer", "operator", "test-runner", "human-viewer", "investigator")

STATES = ("NEW", "VERIFIED", "AVAILABLE", "LEASED", "DRAINING", "QUARANTINED")
_TRANSITIONS: dict[str, frozenset[str]] = {
    "NEW": frozenset({"VERIFIED", "QUARANTINED"}),
    "VERIFIED": frozenset({"AVAILABLE", "QUARANTINED"}),
    "AVAILABLE": frozenset({"LEASED", "QUARANTINED"}),
    "LEASED": frozenset({"DRAINING", "QUARANTINED"}),
    "DRAINING": frozenset({"AVAILABLE", "QUARANTINED"}),
    "QUARANTINED": frozenset(),
}


class RegistryError(RuntimeError):
    """Enrollment or state-machine violation."""


@dataclass(frozen=True)
class Caller:
    """Authenticated caller identity. Never parsed from envelope JSON."""

    identity: str
    roles: tuple[str, ...]
    device_scope: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.identity or len(self.identity) > 128:
            raise RegistryError("caller identity must be 1..128 characters")
        for role in self.roles:
            if role not in CALLER_ROLES:
                raise RegistryError(f"unknown caller role: {role!r}")
        if "*" in self.device_scope:
            raise RegistryError(
                "wildcard device_scope is not permitted; enumerate devices explicitly"
            )
        if not self.device_scope:
            raise RegistryError("caller device_scope must list explicit device ids")


@dataclass(frozen=True)
class Device:
    device_id: str
    serial: str
    pool: str
    hardware_fingerprint: str
    state: str
    quarantine_reason: str | None = None


class OperatorApproval:
    """HMAC-SHA256 operator approval for enrollment and unquarantine.

    The signing key is supplied by the station operator (environment or
    protected file); approvals are deterministic 128+ bit tokens.
    """

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise RegistryError("operator approval key must be at least 16 bytes")
        self._key = bytes(key)

    def payload(self, serial: str, pool: str, device_id: str, fingerprint: str) -> bytes:
        return "|".join(
            (
                "lab-enroll-v1",
                serial,
                pool,
                device_id,
                fingerprint,
            )
        ).encode("utf-8")

    def sign(self, serial: str, pool: str, device_id: str, fingerprint: str) -> str:
        digest = hmac.new(self._key, self.payload(serial, pool, device_id, fingerprint), hashlib.sha256)
        return "v1:" + digest.hexdigest()

    def verify(self, serial: str, pool: str, device_id: str, fingerprint: str, approval: object) -> bool:
        if not isinstance(approval, str):
            return False
        expected = self.sign(serial, pool, device_id, fingerprint)
        return hmac.compare_digest(expected, approval)


class DeviceRegistry:
    """Explicit-allowlist device enrollment with an operator-controlled state machine."""

    def __init__(
        self,
        serial_allowlist: Mapping[str, str],
        approval: OperatorApproval,
    ) -> None:
        if not isinstance(serial_allowlist, Mapping) or not serial_allowlist:
            raise RegistryError("serial allowlist must be a non-empty mapping of serial -> pool")
        for serial, pool in serial_allowlist.items():
            if not isinstance(serial, str) or not SERIAL_PATTERN.fullmatch(serial):
                raise RegistryError(f"allowlist serial is invalid: {serial!r}")
            if pool not in POOLS:
                raise RegistryError(f"allowlist pool is invalid: {pool!r}")
        self._allowlist = dict(serial_allowlist)
        self._approval = approval
        self._by_id: dict[str, Device] = {}
        self._by_serial: dict[str, str] = {}
        self.fingerprint_by_device: dict[str, str] = {}

    @property
    def allowlist(self) -> Mapping[str, str]:
        return dict(self._allowlist)

    def enroll(
        self,
        serial: str,
        *,
        device_id: str,
        hardware_fingerprint: str,
        approval: str | None,
    ) -> Device:
        """Enroll exactly one allowlisted serial. ``approval`` must be valid."""
        if not serial or not isinstance(serial, str):
            raise RegistryError("explicit serial is required; auto-selection is forbidden")
        if not SERIAL_PATTERN.fullmatch(serial):
            raise RegistryError(f"serial contains invalid characters: {serial!r}")
        if serial not in self._allowlist:
            raise RegistryError(f"serial is not on the station allowlist: {serial!r}")
        pool = self._allowlist[serial]
        if not DEVICE_ID_PATTERN.fullmatch(device_id):
            raise RegistryError(f"device_id must match {DEVICE_ID_PATTERN.pattern}: {device_id!r}")
        if device_id in self._by_id:
            raise RegistryError(f"device_id already enrolled: {device_id!r}")
        if serial in self._by_serial:
            raise RegistryError(f"serial already enrolled: {serial!r}")
        if not isinstance(hardware_fingerprint, str) or not 1 <= len(hardware_fingerprint) <= 512:
            raise RegistryError("hardware_fingerprint must be a 1..512 character string")
        if not self._approval.verify(serial, pool, device_id, hardware_fingerprint, approval):
            raise RegistryError(
                f"invalid operator approval for serial {serial!r}; enrollment denied"
            )
        device = Device(
            device_id=device_id,
            serial=serial,
            pool=pool,
            hardware_fingerprint=hardware_fingerprint,
            state="NEW",
        )
        self._by_id[device_id] = device
        self._by_serial[serial] = device_id
        self.fingerprint_by_device[device_id] = hardware_fingerprint
        return device

    def _get(self, device_id: str | None) -> Device:
        if not device_id or not isinstance(device_id, str):
            raise RegistryError("explicit device_id is required; auto-selection is forbidden")
        device = self._by_id.get(device_id)
        if device is None:
            raise RegistryError(f"unknown device_id: {device_id!r}")
        return device

    def get(self, device_id: str | None) -> Device:
        return self._get(device_id)

    def get_by_serial(self, serial: str | None) -> Device:
        if not serial or not isinstance(serial, str) or not SERIAL_PATTERN.fullmatch(serial):
            raise RegistryError("explicit serial is required; auto-selection is forbidden")
        device_id = self._by_serial.get(serial)
        if device_id is None:
            raise RegistryError(f"serial is not enrolled: {serial!r}")
        return self._by_id[device_id]

    def state(self, device_id: str | None) -> str:
        return self._get(device_id).state

    def devices(self) -> tuple[Device, ...]:
        return tuple(self._by_id[key] for key in sorted(self._by_id))

    def _transition(self, device_id: str, to_state: str) -> Device:
        device = self._get(device_id)
        if to_state not in _TRANSITIONS[device.state]:
            raise RegistryError(
                f"invalid transition {device.device_id}: {device.state} -> {to_state}"
            )
        updated = Device(
            device_id=device.device_id,
            serial=device.serial,
            pool=device.pool,
            hardware_fingerprint=device.hardware_fingerprint,
            state=to_state,
            quarantine_reason=None,
        )
        self._by_id[device_id] = updated
        return updated

    def verify_device(self, device_id: str | None) -> Device:
        return self._transition(device_id, "VERIFIED")

    def mark_available(self, device_id: str | None) -> Device:
        return self._transition(device_id, "AVAILABLE")

    def mark_leased(self, device_id: str | None) -> Device:
        return self._transition(device_id, "LEASED")

    def begin_draining(self, device_id: str | None) -> Device:
        return self._transition(device_id, "DRAINING")

    def mark_released(self, device_id: str | None) -> Device:
        """LEASED -> DRAINING; the caller then drains transient content."""
        device = self._get(device_id)
        if device.state != "LEASED":
            raise RegistryError(f"device {device_id!r} is not LEASED (state {device.state})")
        return self.begin_draining(device_id)

    def quarantine(self, device_id: str | None, reason: str) -> Device:
        device = self._get(device_id)
        if not isinstance(reason, str) or not 1 <= len(reason) <= 512:
            raise RegistryError("quarantine reason is required (1..512 characters)")
        if device.state == "QUARANTINED":
            raise RegistryError(f"device {device_id!r} is already quarantined")
        updated = Device(
            device_id=device.device_id,
            serial=device.serial,
            pool=device.pool,
            hardware_fingerprint=device.hardware_fingerprint,
            state="QUARANTINED",
            quarantine_reason=reason,
        )
        self._by_id[device_id] = updated
        return updated

    def unquarantine(self, device_id: str | None, approval: object) -> Device:
        """Operator-approved return from QUARANTINED to VERIFIED."""
        device = self._get(device_id)
        if device.state != "QUARANTINED":
            raise RegistryError(f"device {device_id!r} is not quarantined")
        if not self._approval.verify(
            device.serial, device.pool, device.device_id, device.hardware_fingerprint, approval
        ):
            raise RegistryError(
                f"operator approval required to unquarantine device {device_id!r}"
            )
        updated = Device(
            device_id=device.device_id,
            serial=device.serial,
            pool=device.pool,
            hardware_fingerprint=device.hardware_fingerprint,
            state="VERIFIED",
            quarantine_reason=None,
        )
        self._by_id[device_id] = updated
        return updated


class CallerRegistry:
    """Bearer token -> Caller mapping.

    Tokens are stored only as SHA-256 digests; presentation is compared in
    constant time. Production deployments register identities from the mTLS
    or OIDC connection context instead of raw shared tokens.
    """

    def __init__(self) -> None:
        self._by_digest: dict[str, Caller] = {}

    def register(self, *, token: str, caller: Caller) -> None:
        if not isinstance(token, str) or len(token) < 16:
            raise RegistryError("caller token must be a string of at least 16 characters")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self._by_digest[digest] = caller

    def resolve(self, token: object) -> Caller | None:
        if not isinstance(token, str) or not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        for known, caller in self._by_digest.items():
            if hmac.compare_digest(known, digest):
                return caller
        return None