"""BrokerStation: the station-side enforcement point of the control-plane contract.

Responsibilities (04-CONTROL-PLANE-CONTRACT.md):

* Role-gate every operation; identity arrives from the transport layer, never
  from the request envelope.
* Enforce explicit device enrollment, quarantine, ATS-ownership and pool rules.
* Validate lease fencing (lease_id + generation + caller + device) before any
  device interaction, independently of the gateway.
* Never replay non-idempotent operations after a timeout; return
  ``unknown_outcome`` instead, backed by a bounded idempotency cache.
* Fail closed when the lease backend misbehaves (deny_on_backend_unavailable).
* Keep a payload-free audit ring buffer (request ids and outcomes only).
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from typing import Callable

from station.adb_access import AdbCommandPolicy, collect_inventory, default_run, RunFn
from station.capability_catalog import (
    CapabilityCatalogError,
    PRIVILEGE_TIERS,
    STATION_REFERENCE_CATALOG,
    attest_device,
    canonical_revision,
    validate_catalog,
)
from station.drivers import DriverError, DriverResponse, DriverTimeout, DeviceDriver
from station.lab_policy import (
    LabPolicy,
    KNOWN_OPERATIONS,
    utc_timestamp,
)
from station.leases import LeaseError, LeaseTable
from station.registry import Caller, DeviceRegistry, RegistryError

REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
LEASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

ATS_IDENTITY = "ats-2.0"

# Finished jobs are retained only so `android.tests.status` can answer for a while after
# submission. Queued jobs are never dropped: each one still owns an ATS lease, so forgetting
# one would strand the device. Without a cap a long-lived station grows forever, one entry
# per test submission.
MAX_RETAINED_JOBS = 1000

ROLE_FOR_OPERATION = {
    "android.devices.list": "observer",
    "android.devices.capabilities": "observer",
    "android.devices.attest": "observer",
    "android.api.describe": "observer",
    "android.sessions.acquire": "operator",
    "android.sessions.renew": "operator",
    "android.sessions.release": "operator",
    "android.ui.observe": "operator",
    "android.ui.batch": "operator",
    "android.ui.wait": "operator",
    "android.api.invoke_typed": "operator",
    "android.tests.submit": "test-runner",
    "android.tests.status": "test-runner",
    "android.video.session": "human-viewer",
    "android.logs.query": "investigator",
}

UNSUPPORTED_AT_STATION = frozenset({"android.video.session", "android.logs.query"})

LEASE_REQUIRED_OPERATIONS = frozenset(
    {
        "android.ui.observe",
        "android.ui.batch",
        "android.ui.wait",
        "android.api.invoke_typed",
    }
)

MUTATING_OPERATIONS = LEASE_REQUIRED_OPERATIONS - {"android.ui.observe"}

DRIVER_STATUSES = frozenset(
    {"completed", "denied", "unsupported", "not_tested", "failed", "deadline_exceeded"}
)

MAX_ARGUMENTS_JSON = 8192
MAX_BATCH_STEPS = 20
DEFAULT_DEADLINE_MS = 5000

_ENVELOPE_KEYS = frozenset(
    {
        "request_id",
        "device_id",
        "lease_id",
        "lease_generation",
        "catalog_revision",
        "operation_id",
        "arguments",
        "deadline_ms",
        "idempotency_key",
    }
)

UNKNOWN_OUTCOME = "unknown_outcome"


class BrokerError(ValueError):
    """Malformed request envelope; maps to HTTP 400 at the transport layer."""


def _fail(message: str) -> None:
    raise BrokerError(message)


class BrokerStation:
    """Enforces the station control-plane contract for every tool request."""

    def __init__(
        self,
        *,
        policy: LabPolicy,
        registry: DeviceRegistry,
        leasing: LeaseTable,
        driver: DeviceDriver,
        adb_policy: AdbCommandPolicy,
        adb_runner: RunFn = default_run,
        adb_timeout: int = 2,
        callers: dict[str, Caller] | None = None,
        clock: Callable[[], float] | None = None,
        utc_now: Callable[[], str] | None = None,
        preapproved_tests: frozenset[str] = frozenset(),
        audit_size: int = 512,
        catalog: dict | None = None,
        attested_tier_ceiling: str = "T2_TEST",
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._callers = dict(callers or {})
        self._leasing = leasing
        self._driver = driver
        self._adb_policy = adb_policy
        self._adb_runner = adb_runner
        self._adb_timeout = adb_timeout
        self._clock = clock or time.monotonic
        self._utc_now = utc_now or utc_timestamp
        self._preapproved_tests = frozenset(preapproved_tests)
        self._lock = threading.RLock()
        self._idempotency: dict[tuple[str, str, str, str], tuple[float, object]] = {}
        self._audit: deque[dict] = deque(maxlen=audit_size)
        self._jobs: dict[str, dict] = {}
        self._job_seq = 0
        if attested_tier_ceiling not in PRIVILEGE_TIERS:
            raise CapabilityCatalogError(
                f"unknown attested_tier_ceiling {attested_tier_ceiling!r}"
            )
        self._attested_tier_ceiling = attested_tier_ceiling
        # Device capability catalog (H-12): fail-closed schema validation; the
        # reference catalog is the station-side source of truth for attestation.
        self._catalog = validate_catalog(dict(catalog) if catalog else dict(STATION_REFERENCE_CATALOG))
        self.catalog_revision = canonical_revision(self._catalog)

    # ------------------------------------------------------------------ audit

    def audit_events(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(self._audit)

    def _audit_append(self, request_id, caller, operation_id, device_id, status) -> None:
        with self._lock:
            self._audit.append(
                {
                    "timestamp_utc": self._utc_now(),
                    "request_id": request_id,
                    "caller": caller,
                    "operation_id": operation_id,
                    "device_id": device_id,
                    "status": status,
                }
            )

    # -------------------------------------------------------------- envelope

    def _envelope(self, operation_id: str, envelope: dict) -> dict:
        if not isinstance(envelope, dict):
            _fail("request envelope must be a JSON object")
        for key in envelope:
            if key not in _ENVELOPE_KEYS:
                _fail(f"unknown envelope field: {key!r}")
        envelope_operation = envelope.get("operation_id")
        if envelope_operation is not None:
            if envelope_operation != operation_id:
                _fail("envelope operation_id does not match the routed operation")
        request_id = envelope.get("request_id")
        if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
            _fail("request_id is required and must match ^[A-Za-z0-9_.:-]{1,100}$")
        device_id = envelope.get("device_id")
        if device_id is not None:
            if not isinstance(device_id, str) or not re.fullmatch(r"^[a-z0-9][a-z0-9-]{2,63}$", device_id):
                _fail("device_id must match ^[a-z0-9][a-z0-9-]{2,63}$")
        deadline = envelope.get("deadline_ms", DEFAULT_DEADLINE_MS)
        if isinstance(deadline, bool) or not isinstance(deadline, int) or not 50 <= deadline <= 60000:
            _fail("deadline_ms must be an integer between 50 and 60000")
        arguments = envelope.get("arguments", {})
        if not isinstance(arguments, dict):
            _fail("arguments must be a JSON object")
        arguments_json = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
        if len(arguments_json) > MAX_ARGUMENTS_JSON:
            _fail(f"arguments exceed {MAX_ARGUMENTS_JSON} characters")
        if operation_id == "android.ui.batch":
            steps = arguments.get("steps")
            if not isinstance(steps, list) or not steps or len(steps) > MAX_BATCH_STEPS:
                _fail(f"android.ui.batch requires 1..{MAX_BATCH_STEPS} steps")
            for step in steps:
                if not isinstance(step, dict) or not isinstance(step.get("action"), str) or not step["action"]:
                    _fail("every batch step must be an object with a non-empty 'action'")
        idem_key = envelope.get("idempotency_key")
        if idem_key is not None and (
            not isinstance(idem_key, str)
            or not IDEMPOTENCY_KEY_PATTERN.fullmatch(idem_key)
        ):
            _fail("idempotency_key must match ^[A-Za-z0-9_.:-]{1,128}$")
        # Every device-mutating operation carries an idempotency key so a
        # timed-out attempt can never be silently replayed by a retry.
        if operation_id in MUTATING_OPERATIONS and idem_key is None:
            _fail(f"{operation_id} requires an idempotency_key")
        lease_id = envelope.get("lease_id")
        if lease_id is not None and (
            not isinstance(lease_id, str) or not LEASE_ID_PATTERN.fullmatch(lease_id)
        ):
            _fail("lease_id must match ^[A-Za-z0-9_.:-]{1,128}$")
        generation = envelope.get("lease_generation")
        if generation is not None:
            if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
                _fail("lease_generation must be a positive integer")
        if operation_id in LEASE_REQUIRED_OPERATIONS:
            if lease_id is None:
                _fail(f"{operation_id} requires lease_id")
            if generation is None:
                _fail(f"{operation_id} requires lease_generation")
        return {
            "request_id": request_id,
            "device_id": device_id,
            "lease_id": lease_id,
            "lease_generation": generation,
            "catalog_revision": envelope.get("catalog_revision"),
            "operation_id": operation_id,
            "arguments": arguments,
            "deadline_ms": deadline,
            "idempotency_key": idem_key,
        }

    # ---------------------------------------------------------------- helpers

    def _reap(self) -> bool:
        """Release expired leases. Returns False when a step could not be trusted.

        A failure is reported rather than latched: the caller re-probes on every request, so
        one transient backend hiccup denies that one request instead of wedging the station
        into denying everything until it is restarted.
        """
        healthy = True
        for lease in self._leasing.expire_due():
            try:
                state = self._registry.state(lease.device_id)
                if state == "LEASED":
                    self._registry.mark_released(lease.device_id)
                    if self._policy.station.release_on_lease_expiry:
                        self._registry.mark_available(lease.device_id)
            except Exception:
                healthy = False
        return healthy

    def _deny(self, request_id, caller, operation_id, device_id, error) -> dict:
        return self._respond(
            request_id, device_id, operation_id, "denied", None, error, None, None
        )

    def _respond(
        self,
        request_id: str,
        device_id: str | None,
        operation_id: str | None,
        status: str,
        result: dict | None,
        error: str | None,
        tree_generation: int | None,
        started: float | None,
    ) -> dict:
        elapsed = None if started is None else int((self._clock() - started) * 1000)
        return {
            "request_id": request_id,
            "device_id": device_id,
            "operation_id": operation_id,
            "status": status,
            "started_at_utc": self._utc_now(),
            "elapsed_ms": elapsed,
            "tree_generation": tree_generation,
            "result": result,
            "error": error,
        }

    def _require_device(self, envelope: dict) -> str:
        device_id = envelope["device_id"]
        if not device_id:
            _fail("operation requires a device_id")
        return device_id

    def _idempotent_lookup(
        self,
        device_id: str,
        identity: str,
        operation_id: str,
        key: str | None,
        now: float,
    ):
        if key is None:
            return None
        slot = (device_id, identity, operation_id, key)
        entry = self._idempotency.get(slot)
        if entry is None:
            return None
        expires_at, outcome = entry
        if now > expires_at:
            self._idempotency.pop(slot, None)
            return None
        return outcome

    def _idempotent_store(
        self,
        device_id: str,
        identity: str,
        operation_id: str,
        key: str | None,
        now: float,
        outcome,
    ) -> None:
        if key is None:
            return
        # The slot carries the caller and the operation, not just the caller-supplied key:
        # two identities that happen to choose the same key must not share a slot, and a
        # retry of one operation must not be answered with another operation's result.
        slot = (device_id, identity, operation_id, key)
        ttl = self._policy.session.idempotency_ttl_seconds
        self._idempotency[slot] = (now + ttl, outcome)

    # --------------------------------------------------------------- execute

    def execute(self, caller: Caller, operation_id: str, envelope: dict) -> dict:
        try:
            env = self._envelope(operation_id, envelope)
        except BrokerError:
            raise
        request_id = env["request_id"]
        device_id = env["device_id"]
        started = self._clock()
        audit = lambda status: self._audit_append(
            request_id, caller.identity, operation_id, device_id, status
        )

        try:
            # Re-probe on every request instead of latching: a sticky flag let a single
            # transient backend error deny the whole lab until the process restarted.
            backend_healthy = self._reap()
        except Exception:
            backend_healthy = False
        if not backend_healthy:
            audit("denied")
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                "station backend unavailable; denying by policy",
            )

        response = self._dispatch(caller, operation_id, env, started)
        audit(response["status"])
        return response

    def _dispatch(self, caller, operation_id, env, started) -> dict:
        request_id, device_id = env["request_id"], env["device_id"]
        revision = env["catalog_revision"]
        if revision is not None and revision != self.catalog_revision:
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                "catalog_revision mismatch: gateway catalog is stale",
            )

        if operation_id not in KNOWN_OPERATIONS:
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                "operation is not known to this station (deny_by_default)",
            )
        if operation_id in UNSUPPORTED_AT_STATION:
            return self._respond(
                request_id, device_id, operation_id, "unsupported", None,
                "operation is not supported by this station; use the authorized "
                "human session path", None, started,
            )
        if operation_id not in self._policy.station.allowed_operations:
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                "operation is forbidden by station policy",
            )
        required_role = ROLE_FOR_OPERATION[operation_id]
        if required_role not in caller.roles:
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                f"caller requires role {required_role!r} for this operation",
            )

        handler = {
            "android.devices.list": self._op_devices_list,
            "android.devices.capabilities": self._op_devices_capabilities,
            "android.devices.attest": self._op_devices_attest,
            "android.api.describe": self._op_api_describe,
            "android.sessions.acquire": self._op_sessions_acquire,
            "android.sessions.renew": self._op_sessions_renew,
            "android.sessions.release": self._op_sessions_release,
            "android.ui.observe": self._op_driver_operation,
            "android.ui.batch": self._op_driver_operation,
            "android.ui.wait": self._op_driver_operation,
            "android.api.invoke_typed": self._op_driver_operation,
            "android.tests.submit": self._op_tests_submit,
            "android.tests.status": self._op_tests_status,
        }[operation_id]
        try:
            return handler(caller, env, started)
        except BrokerError:
            raise
        except LeaseError as ex:
            return self._deny(
                request_id, caller.identity, operation_id, device_id, f"lease rejected: {ex}"
            )
        except RegistryError as ex:
            return self._deny(
                request_id, caller.identity, operation_id, device_id, f"device rejected: {ex}"
            )
        except Exception:
            if not self._policy.session.deny_on_backend_unavailable:
                raise
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                "station backend unavailable; denying by policy",
            )

    # ------------------------------------------------------------ device gate

    def _gate_device(self, caller, device_id) -> None:
        device = self._registry.get(device_id)
        if device.state == "QUARANTINED":
            raise LeaseError(
                f"device {device_id!r} is quarantined"
                + (f": {device.quarantine_reason}" if device.quarantine_reason else "")
            )
        if caller.identity != ATS_IDENTITY and device_id not in caller.device_scope:
            raise LeaseError(
                f"caller {caller.identity!r} is not scoped to device {device_id!r}"
            )
        if device.pool == "privileged" and caller.identity != ATS_IDENTITY:
            if not self._policy.privileged_pool.enabled:
                raise LeaseError("privileged pool is disabled by station policy")
            if not self._policy.privileged_pool.requires_operator_approval:
                raise LeaseError("privileged pool policy invariant broken")
            # Operator approval is required in every lifecycle state. Keying this on AVAILABLE
            # let a non-operator reach a privileged device while it was still NEW or VERIFIED:
            # android.devices.attest needs only the observer role and runs before the device is
            # ever offered, so an observer could attest a privileged device unapproved.
            if "operator" not in caller.roles:
                raise LeaseError("privileged pool requires an approved operator")

    def _ats_owned(self, device_id: str) -> bool:
        lease = self._leasing.active_lease(device_id)
        return lease is not None and lease.caller == ATS_IDENTITY

    # ------------------------------------------------------------- operations

    def _op_devices_list(self, caller, env, started) -> dict:
        devices = []
        is_operator = "operator" in caller.roles
        for device in self._registry.devices():
            if caller.identity != ATS_IDENTITY and device.device_id not in caller.device_scope:
                continue
            entry = {
                "device_id": device.device_id,
                "pool": device.pool,
                "state": device.state,
            }
            if is_operator:
                entry["serial"] = device.serial
            devices.append(entry)
        payload = {
            "devices": devices,
            "catalog_revision": self.catalog_revision,
        }
        # The ATS-owned list is built from the whole registry, not from caller.device_scope,
        # so handing it to every observer would let an observer enumerate leases held by
        # other callers across the entire pool. Report it to the scheduler and operators only.
        if caller.identity == ATS_IDENTITY or is_operator:
            payload["ats_owned_devices"] = sorted(
                d.device_id for d in self._registry.devices() if self._ats_owned(d.device_id)
            )
        return self._respond(
            env["request_id"], None, "android.devices.list", "completed",
            payload, None, None, started,
        )

    def _op_devices_capabilities(self, caller, env, started) -> dict:
        device_id = self._require_device(env)
        try:
            self._gate_device(caller, device_id)
            device = self._registry.get(device_id)
            inventory = self._inventory(device)
        except LeaseError as ex:
            return self._deny(
                env["request_id"], caller.identity, "android.devices.capabilities",
                device_id, str(ex),
            )
        except RegistryError:
            raise  # mapped to "device rejected" by the dispatcher
        except RuntimeError as ex:
            return self._respond(
                env["request_id"], device_id, "android.devices.capabilities", "failed",
                None, f"capability probe failed: {ex}", None, started,
            )
        if "operator" not in caller.roles:
            inventory = dict(inventory)
            inventory["serial"] = None
            inventory["props"] = {
                key: value for key, value in inventory["props"].items()
                if key != "ro.build.fingerprint"
            }
        return self._respond(
            env["request_id"], device_id, "android.devices.capabilities", "completed",
            inventory, None, None, started,
        )

    def _inventory(self, device) -> dict:
        return collect_inventory(
            device.serial,
            self._adb_policy,
            runner=self._adb_runner,
            timeout=self._adb_timeout,
        )

    def _op_api_describe(self, caller, env, started) -> dict:
        return self._respond(
            env["request_id"], None, "android.api.describe", "completed",
            {
                "catalog": self._catalog,
                "catalog_revision": self.catalog_revision,
                "supported_operations": sorted(self._policy.station.allowed_operations),
            },
            None, None, started,
        )

    def _op_devices_attest(self, caller, env, started) -> dict:
        device_id = self._require_device(env)
        arguments = env["arguments"]
        device_catalog = arguments.get("catalog")
        if not isinstance(device_catalog, dict):
            return self._respond(
                env["request_id"], device_id, "android.devices.attest", "failed",
                None, "attestation requires a 'catalog' object argument", None, started,
            )
        try:
            self._gate_device(caller, device_id)
        except LeaseError as ex:
            return self._deny(
                env["request_id"], caller.identity, "android.devices.attest",
                device_id, str(ex),
            )
        except RegistryError:
            raise  # mapped to "device rejected" by the dispatcher
        try:
            attestation = attest_device(
                device_catalog,
                device_catalog_revision=arguments.get("device_catalog_revision"),
                reference_catalog=self._catalog,
                tier_ceiling=self._attested_tier_ceiling,
                catalog_revision=self.catalog_revision,
            )
        except CapabilityCatalogError as ex:
            return self._respond(
                env["request_id"], device_id, "android.devices.attest", "failed",
                None, f"capability catalog is invalid: {ex}", None, started,
            )
        return self._respond(
            env["request_id"], device_id, "android.devices.attest", "completed",
            attestation, None, None, started,
        )

    def _op_sessions_acquire(self, caller, env, started) -> dict:
        device_id = self._require_device(env)
        if self._ats_owned(device_id):
            return self._deny(
                env["request_id"], caller.identity, "android.sessions.acquire", device_id,
                "device is owned by the automated test scheduler and unavailable "
                "to interactive workers",
            )
        self._gate_device(caller, device_id)
        device = self._registry.get(device_id)
        if device.state != "AVAILABLE":
            return self._deny(
                env["request_id"], caller.identity, "android.sessions.acquire", device_id,
                f"device state is {device.state!r}; lease requires AVAILABLE",
            )
        lease = self._leasing.acquire(device_id, caller.identity)
        self._registry.mark_leased(device_id)
        return self._respond(
            env["request_id"], device_id, "android.sessions.acquire", "completed",
            {
                "lease_id": lease.lease_id,
                "lease_generation": lease.generation,
                "lease_ttl_seconds": lease.ttl_seconds,
                "device_pool": device.pool,
            },
            None, None, started,
        )

    def _op_sessions_renew(self, caller, env, started) -> dict:
        device_id = self._require_device(env)
        if env["lease_id"] is None or env["lease_generation"] is None:
            _fail("android.sessions.renew requires lease_id and lease_generation")
        try:
            self._gate_device(caller, device_id)
            self._registry.get(device_id)
        except LeaseError as ex:
            return self._deny(
                env["request_id"], caller.identity, "android.sessions.renew", device_id, str(ex)
            )
        lease = self._leasing.renew(
            device_id=device_id,
            lease_id=env["lease_id"],
            caller=caller.identity,
            generation=env["lease_generation"],
        )
        return self._respond(
            env["request_id"], device_id, "android.sessions.renew", "completed",
            {
                "lease_id": lease.lease_id,
                "lease_generation": lease.generation,
                "lease_ttl_seconds": lease.ttl_seconds,
            },
            None, None, started,
        )

    def _op_sessions_release(self, caller, env, started) -> dict:
        device_id = self._require_device(env)
        if env["lease_id"] is None or env["lease_generation"] is None:
            _fail("android.sessions.release requires lease_id and lease_generation")
        try:
            self._gate_device(caller, device_id)
            self._registry.get(device_id)
        except LeaseError as ex:
            return self._deny(
                env["request_id"], caller.identity, "android.sessions.release", device_id, str(ex)
            )
        lease = self._leasing.release(
            device_id=device_id,
            lease_id=env["lease_id"],
            caller=caller.identity,
            generation=env["lease_generation"],
        )
        if lease is not None:
            self._registry.mark_released(device_id)
            if self._policy.station.release_on_lease_expiry:
                self._registry.mark_available(device_id)
        self._scrub_transient(device_id)
        return self._respond(
            env["request_id"], device_id, "android.sessions.release", "completed",
            {"released": lease is not None}, None, None, started,
        )

    def _scrub_transient(self, device_id: str) -> None:
        for key in [k for k in self._idempotency if k[0] == device_id]:
            self._idempotency.pop(key, None)

    def _validate_lease(self, caller, env):
        device_id = self._require_device(env)
        self._registry.get(device_id)
        return self._leasing.validate(
            device_id=device_id,
            lease_id=env["lease_id"],
            caller=caller.identity,
            generation=env["lease_generation"],
        )

    def _op_driver_operation(self, caller, env, started) -> dict:
        operation_id = env["operation_id"]
        request_id, device_id = env["request_id"], env["device_id"]
        now = self._clock()
        try:
            self._gate_device(caller, device_id)
        except LeaseError as ex:
            return self._deny(request_id, caller.identity, operation_id, device_id, str(ex))

        # The idempotency cache answers before lease validation: a retry that
        # carries the same key must never re-run device work, even when the
        # original lease has since expired.
        replay = self._idempotent_lookup(
            device_id, caller.identity, operation_id, env["idempotency_key"], now
        )
        if replay is not None:
            if replay == UNKNOWN_OUTCOME:
                return self._respond(
                    request_id, device_id, operation_id, UNKNOWN_OUTCOME, None,
                    "a previous attempt timed out; refusing to replay a non-idempotent "
                    "operation", None, started,
                )
            recorded = dict(replay)
            recorded["request_id"] = request_id
            return recorded

        try:
            self._validate_lease(caller, env)
        except LeaseError as ex:
            return self._deny(request_id, caller.identity, operation_id, device_id, str(ex))

        timeout_seconds = max(0.05, env["deadline_ms"] / 1000.0)
        try:
            driver_response = self._driver.perform(
                device_id, operation_id, env["arguments"], timeout_seconds
            )
        except DriverTimeout:
            if operation_id in MUTATING_OPERATIONS:
                self._idempotent_store(
                    device_id,
                    caller.identity,
                    operation_id,
                    env["idempotency_key"],
                    now,
                    UNKNOWN_OUTCOME,
                )
                return self._respond(
                    request_id, device_id, operation_id, UNKNOWN_OUTCOME, None,
                    "deadline exceeded before the driver confirmed the operation; "
                    "outcome unknown and replay refused", None, started,
                )
            return self._respond(
                request_id, device_id, operation_id, "deadline_exceeded", None,
                f"driver exceeded the {env['deadline_ms']}ms deadline", None, started,
            )
        except DriverError as ex:
            return self._respond(
                request_id, device_id, operation_id, "failed", None,
                f"driver failed: {ex}", None, started,
            )

        if operation_id in MUTATING_OPERATIONS:
            try:
                self._validate_lease(caller, env)
            except LeaseError as ex:
                self._idempotent_store(
                    device_id,
                    caller.identity,
                    operation_id,
                    env["idempotency_key"],
                    now,
                    UNKNOWN_OUTCOME,
                )
                return self._respond(
                    request_id, device_id, operation_id, UNKNOWN_OUTCOME, None,
                    f"lease no longer valid after execution ({ex}); outcome unknown "
                    "and replay refused", None, started,
                )

        status = driver_response.status
        if status not in DRIVER_STATUSES:
            status = "failed"
            driver_response = DriverResponse(
                status="failed",
                result=None,
                tree_generation=driver_response.tree_generation,
                error=f"driver returned invalid status: {driver_response.status!r}",
            )
        if status == "completed":
            self._idempotent_store(
                device_id,
                caller.identity,
                operation_id,
                env["idempotency_key"],
                now,
                dict(
                    self._respond(
                        request_id, device_id, operation_id, status,
                        driver_response.result, driver_response.error,
                        driver_response.tree_generation, started,
                    )
                ),
            )
        return self._respond(
            request_id, device_id, operation_id, status, driver_response.result,
            driver_response.error, driver_response.tree_generation, started,
        )

    # ------------------------------------------------------------ tests / ATS

    def _op_tests_submit(self, caller, env, started) -> dict:
        operation_id = "android.tests.submit"
        request_id, device_id = env["request_id"], env["device_id"]
        arguments = env["arguments"]
        test_name = arguments.get("test_name")
        if not isinstance(test_name, str) or not re.fullmatch(r"^[A-Za-z0-9_.:#/\[\]-]{1,200}$", test_name):
            _fail("android.tests.submit requires a 'test_name' argument")
        if device_id is None:
            _fail("android.tests.submit requires a device_id")
        if self._ats_owned(device_id):
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                "device is already owned by the automated test scheduler",
            )
        try:
            self._gate_device(caller, device_id)
        except LeaseError as ex:
            return self._deny(request_id, caller.identity, operation_id, device_id, str(ex))
        device = self._registry.get(device_id)
        if device.pool != "scheduled":
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                "android.tests.submit requires a scheduled-pool device",
            )
        if test_name not in self._preapproved_tests:
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                f"test {test_name!r} is not preapproved for scheduler submission",
            )
        if device.state != "AVAILABLE":
            return self._deny(
                request_id, caller.identity, operation_id, device_id,
                f"device state is {device.state!r}; submission requires AVAILABLE",
            )
        self._registry.get(device_id)
        lease = self._leasing.acquire(device_id, ATS_IDENTITY)
        self._registry.mark_leased(device_id)
        with self._lock:
            self._job_seq += 1
            job_id = f"job-{self._job_seq:04d}"
            self._jobs[job_id] = {
                "job_id": job_id,
                "test_name": test_name,
                "device_id": device_id,
                "status": "queued",
                "submitter": caller.identity,
                "lease_id": lease.lease_id,
                "lease_generation": lease.generation,
                "submitted_at_utc": self._utc_now(),
            }
            self._prune_jobs()
        return self._respond(
            request_id, device_id, operation_id, "completed",
            {"job_id": job_id, "status": "queued", "lease_id": lease.lease_id,
             "lease_generation": lease.generation},
            None, None, started,
        )

    def _op_tests_status(self, caller, env, started) -> dict:
        operation_id = "android.tests.status"
        request_id = env["request_id"]
        job_id = env["arguments"].get("job_id")
        if not isinstance(job_id, str) or not re.fullmatch(r"^job-[0-9]{4,}$", job_id):
            _fail("android.tests.status requires a 'job_id' argument")
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return self._deny(
                request_id, caller.identity, operation_id, env["device_id"],
                f"unknown job {job_id!r}",
            )
        if caller.identity != ATS_IDENTITY and job["submitter"] != caller.identity:
            return self._deny(
                request_id, caller.identity, operation_id, env["device_id"],
                "only the submitting identity or the scheduler may query this job",
            )
        return self._respond(
            request_id, job["device_id"], operation_id, "completed",
            {
                "job_id": job["job_id"],
                "test_name": job["test_name"],
                "device_id": job["device_id"],
                "status": job["status"],
                "lease_generation": job["lease_generation"],
                "submitted_at_utc": job["submitted_at_utc"],
            },
            None, None, started,
        )

    # ---------------------------------------------- internal scheduler hooks

    def _prune_jobs(self) -> None:
        """Drop the oldest finished jobs once the retained set exceeds its cap.

        Caller holds ``self._lock``. Insertion order is oldest first. A queued job is normally
        kept because a device is still holding its lease and dropping the entry would strand
        that device. An *orphaned* queued job — one whose device no longer holds the lease the
        job was submitted against, because the lease expired, was released, or the release
        itself failed inside :meth:`complete_job` — can never be completed, so it is a pure
        leak and is dropped like a finished one. A late ``complete_job`` for such an entry then
        fails with "not in a completable state", which is already the correct outcome.
        """
        if len(self._jobs) <= MAX_RETAINED_JOBS:
            return
        for job_id in list(self._jobs):
            if len(self._jobs) <= MAX_RETAINED_JOBS:
                return
            job = self._jobs[job_id]
            if job["status"] == "queued" and not self._job_owns_its_lease(job):
                del self._jobs[job_id]
            elif job["status"] != "queued":
                del self._jobs[job_id]

    def _job_owns_its_lease(self, job: dict) -> bool:
        """Whether ``job``'s device still holds the exact lease the job was submitted against."""
        lease = self._leasing.active_lease(job["device_id"])
        return (
            lease is not None
            and lease.lease_id == job["lease_id"]
            and lease.generation == job["lease_generation"]
        )

    def complete_job(self, job_id: str) -> None:
        """Scheduler hook: finish a queued job and release the ATS lease."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job["status"] != "queued":
                raise BrokerError(f"job {job_id!r} is not in a completable state")
        self._leasing.release(
            device_id=job["device_id"],
            lease_id=job["lease_id"],
            caller=ATS_IDENTITY,
            generation=job["lease_generation"],
        )
        self._registry.mark_released(job["device_id"])
        self._registry.mark_available(job["device_id"])
        job["status"] = "completed"
        self._scrub_transient(job["device_id"])