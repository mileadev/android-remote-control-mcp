"""Hardened Android MCP lab station (Python control plane).

Implements the handoff item H-09 (station/ADB hardening) and the station
control-plane contract:

- lab policy loading with strict, fail-closed validation (`lab_policy`);
- explicit device serial allowlist and enrollment with operator approval
  (`registry`);
- exclusive, generation-fenced, expiring device leases (`leases`);
- ADB access control: read-only inventory commands, forward-port registry
  with collision checks, forbidden-port enforcement (`adb_access`);
- typed device drivers behind a narrow interface (`drivers`);
- the broker that independently validates leases/tool policy regardless of
  gateway claims (`broker`);
- a loopback-only JSON/HTTP control plane (`http_api`).

Standard library only. The station refuses to fail open: missing policy,
unknown operations, absent/expired/mismatched leases or backend faults deny
the operation.
"""

__all__ = [
    "adb_access",
    "broker",
    "drivers",
    "http_api",
    "lab_policy",
    "leases",
    "registry",
]