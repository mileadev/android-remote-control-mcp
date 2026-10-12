"""Exclusive, generation-fenced, expiring device lease table.

Invariants (control-plane contract):

1. At most one active lease per device; acquiring a leased device fails with
   ``DeviceBusy``.
2. Every new lease increments a per-device ``lease_generation`` fencing token
   that is never reused, even across restarts or after expiry.
3. Renew requires the same identity *and* the same generation; release
   requires a matching lease and generation.
4. Leases expire based on an injected monotonic clock, so expiry is
   deterministic and immune to wall-clock skew. Expired leases are returned
   by ``expire_due`` so the broker can transition the device safely.

The table is an independent station-side authority: gateway retries with
stale generations, other identities, or another device's lease are denied.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from typing import Callable


class LeaseError(RuntimeError):
    """Base class for lease validation failures (fail closed)."""


class UnknownLease(LeaseError):
    pass


class GenerationStale(LeaseError):
    pass


class LeaseDeviceMismatch(LeaseError):
    pass


class LeaseCallerMismatch(LeaseError):
    pass


class LeaseExpired(LeaseError):
    pass


class DeviceBusy(LeaseError):
    pass


@dataclass(frozen=True)
class Lease:
    lease_id: str
    device_id: str
    caller: str
    generation: int
    acquired_at: float
    expires_at: float

    @property
    def ttl_seconds(self) -> int:
        return max(0, int(round(self.expires_at - self.acquired_at)))


LeaseIdFactory = Callable[[], str]
Clock = Callable[[], float]


class LeaseTable:
    """Thread-safe lease store with monotonic per-device fencing generations."""

    def __init__(
        self,
        *,
        ttl_seconds: float,
        clock: Clock | None = None,
        id_factory: LeaseIdFactory | None = None,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
            raise ValueError("ttl_seconds must be a number")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive number")
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self._ttl = float(ttl_seconds)
        self._clock = clock
        self._id_factory = id_factory or (lambda: secrets.token_urlsafe(24))
        self._lock = threading.RLock()
        self._by_id: dict[str, Lease] = {}
        self._by_device: dict[str, Lease] = {}
        self._generations: dict[str, int] = {}

    @staticmethod
    def _default_clock() -> float:
        import time

        return time.monotonic()

    def _now(self) -> float:
        if self._clock is None:
            return self._default_clock()
        return self._clock()

    def _expired(self, lease: Lease, now: float) -> bool:
        return now >= lease.expires_at

    def acquire(self, device_id: str, caller: str) -> Lease:
        if not device_id or not caller or not isinstance(device_id, str) or not isinstance(caller, str):
            raise LeaseError("device_id and caller are required")
        with self._lock:
            now = self._now()
            self._evict_expired(now)
            if device_id in self._by_device:
                raise DeviceBusy(f"device {device_id!r} already holds an active lease")
            generation = self._generations.get(device_id, 0) + 1
            self._generations[device_id] = generation
            lease_id = self._id_factory()
            if lease_id in self._by_id:
                raise LeaseError("lease id collision; refusing to overwrite an active lease")
            lease = Lease(
                lease_id=lease_id,
                device_id=device_id,
                caller=caller,
                generation=generation,
                acquired_at=now,
                expires_at=now + self._ttl,
            )
            self._by_device[device_id] = lease
            self._by_id[lease.lease_id] = lease
            return lease

    def renew(
        self, *, device_id: str, lease_id: str, caller: str, generation: int
    ) -> Lease:
        with self._lock:
            now = self._now()
            lease = self._validate_locked(device_id, lease_id, caller, generation, now)
            renewed = Lease(
                lease_id=lease.lease_id,
                device_id=lease.device_id,
                caller=lease.caller,
                generation=lease.generation,
                acquired_at=lease.acquired_at,
                expires_at=now + self._ttl,
            )
            self._by_id[lease.lease_id] = renewed
            self._by_device[lease.device_id] = renewed
            return renewed

    def release(
        self, *, device_id: str, lease_id: str, caller: str, generation: int
    ) -> Lease | None:
        """Release a lease. Releasing an already-expired lease is a no-op."""
        with self._lock:
            now = self._now()
            try:
                lease = self._validate_locked(device_id, lease_id, caller, generation, now)
            except LeaseExpired:
                return None
        with self._lock:
            self._by_id.pop(lease.lease_id, None)
            if self._by_device.get(device_id) is lease:
                self._by_device.pop(device_id, None)
            return lease

    def validate(
        self, *, device_id: str, lease_id: str, caller: str, generation: int
    ) -> Lease:
        with self._lock:
            return self._validate_locked(device_id, lease_id, caller, generation, self._now())

    def _validate_locked(
        self, device_id: str, lease_id: str, caller: str, generation: int, now: float
    ) -> Lease:
        if not isinstance(lease_id, str) or not lease_id:
            raise UnknownLease("lease_id is required")
        lease = self._by_id.get(lease_id)
        if lease is None:
            raise UnknownLease(f"unknown lease_id: {lease_id!r}")
        if lease.device_id != device_id:
            raise LeaseDeviceMismatch("lease belongs to a different device")
        if lease.caller != caller:
            raise LeaseCallerMismatch("lease belongs to a different caller")
        if generation != lease.generation:
            raise GenerationStale("lease generation is stale")
        if self._expired(lease, now):
            # Deliberately not dropped here: ``expire_due`` owns expiry
            # bookkeeping so the broker can transition the device safely.
            raise LeaseExpired("lease has expired")
        return lease

    def _drop_locked(self, lease: Lease) -> None:
        self._by_id.pop(lease.lease_id, None)
        if self._by_device.get(lease.device_id) is lease:
            self._by_device.pop(lease.device_id, None)

    def _evict_expired(self, now: float) -> None:
        for lease in list(self._by_id.values()):
            if self._expired(lease, now):
                self._drop_locked(lease)

    def expire_due(self) -> tuple[Lease, ...]:
        """Drop and return all leases that have expired by now."""
        with self._lock:
            now = self._now()
            expired = tuple(
                lease for lease in list(self._by_id.values()) if self._expired(lease, now)
            )
            for lease in expired:
                self._drop_locked(lease)
            return expired

    def active_lease(self, device_id: str) -> Lease | None:
        """The lease still registered for the device, even if past expiry.

        ``expire_due`` purges expired leases; callers that need to react to
        expiry (e.g. device state transitions) should call it first.
        """
        with self._lock:
            return self._by_device.get(device_id)

    def generation(self, device_id: str) -> int:
        with self._lock:
            return self._generations.get(device_id, 0)

    def snapshot(self) -> tuple[Lease, ...]:
        with self._lock:
            self._evict_expired(self._now())
            return tuple(self._by_id.values())