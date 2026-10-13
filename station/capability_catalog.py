"""Capability catalog validation and attestation (H-12, 04-CONTROL-PLANE-CONTRACT.md).

The station keeps a fail-closed view of the device capability catalog:

* every catalog entry must carry exactly the 12 contract keys (no extras, no
  gaps) with contract-typed values;
* the revision is the sha256 of the canonical JSON encoding
  (``json.dumps(..., sort_keys=True, separators=(",", ":"))``) so a station
  and a device that agree on the entry set agree on the revision byte-for-byte;
* attestation compares a device-supplied catalog against the station reference
  catalog and a station-configured privilege-tier ceiling, reporting typed
  violations (must fix) and drift (must reconcile) instead of guessing.

Parsing is fail-closed: any malformed catalog raises [CapabilityCatalogError]
rather than being coerced into something plausible.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

PRIVILEGE_TIERS: tuple[str, ...] = (
    "T1_APP",
    "T2_TEST",
    "T3_MANAGED",
    "T4_USERDEBUG",
    "T5_PLATFORM",
)

CAPABILITY_ENTRY_KEYS = frozenset(
    {
        "api_id",
        "adapter_id",
        "platform",
        "min_api_level",
        "max_api_level",
        "privilege_tier",
        "required_permissions",
        "hardware_features",
        "argument_schema_revision",
        "risk",
        "device_status",
        "verification",
    }
)

VERIFICATION_KEYS = frozenset({"test_id", "apk_sha256", "timestamp_utc"})

RISK_LABELS = frozenset({"read_only", "mutating", "destructive", "network"})
DEVICE_STATUSES = frozenset({"verified", "not_tested"})
PLATFORMS = frozenset({"android"})

API_ID_PATTERN = re.compile(r"^android\.[a-z][a-z0-9_.]{1,63}$")
ADAPTER_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
PERMISSION_PATTERN = re.compile(r"^android\.permission\.[A-Z0-9_.]+$")
HARDWARE_PATTERN = re.compile(r"^android\.hardware\.[a-z0-9_.]+$")
ARGUMENT_SCHEMA_REVISION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")

MIN_APP_API_LEVEL = 33


class CapabilityCatalogError(ValueError):
    """A capability catalog (or entry) violates the contract schema."""


def tier_rank(tier: str) -> int:
    """Rank of a privilege tier (1 = T1_APP ... 5 = T5_PLATFORM).

    Raises [CapabilityCatalogError] for unknown tiers (fail closed).
    """
    try:
        return PRIVILEGE_TIERS.index(tier) + 1
    except ValueError:
        raise CapabilityCatalogError(f"unknown privilege tier {tier!r}") from None


def validate_entry(api_id: str, entry: object) -> dict:
    """Validate one catalog entry against the contract schema (fail closed)."""
    if not isinstance(api_id, str) or not API_ID_PATTERN.match(api_id):
        raise CapabilityCatalogError(f"catalog api_id {api_id!r} is not a valid operation id")
    if not isinstance(entry, dict):
        raise CapabilityCatalogError(f"catalog entry {api_id!r} is not an object")
    if set(entry.keys()) != CAPABILITY_ENTRY_KEYS:
        extra = sorted(set(entry.keys()) - CAPABILITY_ENTRY_KEYS)
        missing = sorted(CAPABILITY_ENTRY_KEYS - set(entry.keys()))
        raise CapabilityCatalogError(
            f"catalog entry {api_id!r} key set mismatch "
            f"(unexpected={extra}, missing={missing})"
        )
    if entry["api_id"] != api_id:
        raise CapabilityCatalogError(
            f"catalog entry key {api_id!r} disagrees with entry api_id {entry['api_id']!r}"
        )
    for key in ("api_id", "adapter_id", "platform", "argument_schema_revision"):
        if not isinstance(entry[key], str) or not entry[key]:
            raise CapabilityCatalogError(f"catalog entry {api_id!r}: {key} must be a non-empty string")
    if not ARGUMENT_SCHEMA_REVISION_PATTERN.match(entry["argument_schema_revision"]):
        raise CapabilityCatalogError(
            f"catalog entry {api_id!r}: argument_schema_revision "
            f"{entry['argument_schema_revision']!r} is invalid"
        )
    if not ADAPTER_ID_PATTERN.match(entry["adapter_id"]):
        raise CapabilityCatalogError(
            f"catalog entry {api_id!r}: adapter_id {entry['adapter_id']!r} is invalid"
        )
    if entry["platform"] not in PLATFORMS:
        raise CapabilityCatalogError(f"catalog entry {api_id!r}: unsupported platform {entry['platform']!r}")
    if entry["privilege_tier"] not in PRIVILEGE_TIERS:
        raise CapabilityCatalogError(
            f"catalog entry {api_id!r}: unknown privilege_tier {entry['privilege_tier']!r}"
        )
    if entry["risk"] not in RISK_LABELS:
        raise CapabilityCatalogError(f"catalog entry {api_id!r}: unknown risk {entry['risk']!r}")
    if entry["device_status"] not in DEVICE_STATUSES:
        raise CapabilityCatalogError(
            f"catalog entry {api_id!r}: unknown device_status {entry['device_status']!r}"
        )
    min_level = entry["min_api_level"]
    max_level = entry["max_api_level"]
    if isinstance(min_level, bool) or not isinstance(min_level, int) or min_level < 1:
        raise CapabilityCatalogError(f"catalog entry {api_id!r}: min_api_level must be a positive integer")
    if not (max_level is None or (not isinstance(max_level, bool) and isinstance(max_level, int))):
        raise CapabilityCatalogError(f"catalog entry {api_id!r}: max_api_level must be null or an integer")
    if max_level is not None and max_level < min_level:
        raise CapabilityCatalogError(f"catalog entry {api_id!r}: max_api_level is below min_api_level")
    if int(min_level) < MIN_APP_API_LEVEL:
        raise CapabilityCatalogError(
            f"catalog entry {api_id!r}: min_api_level {min_level} is below the supported "
            f"MIN_APP_API_LEVEL {MIN_APP_API_LEVEL}"
        )
    for key in ("required_permissions", "hardware_features"):
        values = entry[key]
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise CapabilityCatalogError(f"catalog entry {api_id!r}: {key} must be a list of strings")
        pattern = PERMISSION_PATTERN if key == "required_permissions" else HARDWARE_PATTERN
        for value in values:
            if not pattern.match(value):
                raise CapabilityCatalogError(
                    f"catalog entry {api_id!r}: {key} value {value!r} is invalid"
                )
    verification = entry["verification"]
    if not isinstance(verification, dict):
        raise CapabilityCatalogError(f"catalog entry {api_id!r}: verification must be an object")
    if set(verification.keys()) != VERIFICATION_KEYS:
        raise CapabilityCatalogError(
            f"catalog entry {api_id!r}: verification key set mismatch (expected exactly test_id, "
            "apk_sha256, timestamp_utc)"
        )
    if entry["device_status"] == "verified":
        filled = all(
            isinstance(verification[key], str) and verification[key]
            for key in VERIFICATION_KEYS
        )
        if not filled:
            raise CapabilityCatalogError(
                f"catalog entry {api_id!r}: verified capability requires full test evidence"
            )
    else:
        if any(verification[key] is not None for key in VERIFICATION_KEYS):
            raise CapabilityCatalogError(
                f"catalog entry {api_id!r}: untested capability must not carry test evidence"
            )
    return entry


def validate_catalog(catalog: object) -> dict:
    """Validate a whole catalog (api_id-keyed object) and return it unchanged."""
    if not isinstance(catalog, dict):
        raise CapabilityCatalogError("capability catalog must be an object keyed by api_id")
    for api_id, entry in catalogue_items(catalog):
        validate_entry(api_id, entry)
    return catalog


def catalogue_items(catalog: dict) -> tuple[tuple[str, object], ...]:
    """Deterministic iteration order for a catalog (sorted by api_id)."""
    return tuple(sorted(catalog.items()))


def canonical_revision(catalog: Mapping[str, dict]) -> str:
    """Revision string for a catalog: sha256 of its canonical JSON encoding."""
    encoded = json.dumps(dict(catalog), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def attest_device_catalog(
    device_catalog: object,
    *,
    reference_catalog: Mapping[str, dict],
    tier_ceiling: str = "T2_TEST",
) -> tuple[list[str], list[str]]:
    """Compare a device catalog against the station reference catalog and ceiling.

    Returns ``(violations, drift)``. Violations are attestation failures the
    device must fix (unlisted capability or tier above the ceiling); drift is a
    mismatch between device and reference entry bodies. Both inputs are
    validated fail-closed first; malformed catalogs raise, never attest.
    """
    validate_catalog(dict(device_catalog))
    validate_catalog(dict(reference_catalog))
    ceiling = tier_rank(tier_ceiling)
    violations: list[str] = []
    drift: list[str] = []
    for api_id, entry in catalogue_items(dict(device_catalog)):
        reference = reference_catalog.get(api_id)
        if reference is None:
            violations.append(f"{api_id} is not listed in the station reference catalog")
            continue
        if tier_rank(entry["privilege_tier"]) > ceiling:
            violations.append(
                f"{api_id} privilege_tier {entry['privilege_tier']} exceeds the station "
                f"ceiling {tier_ceiling}"
            )
            continue
        if dict(entry) != dict(reference):
            drift.append(f"{api_id} differs from the station reference catalog")
    for api_id, _entry in catalogue_items(dict(reference_catalog)):
        if api_id not in dict(device_catalog):
            drift.append(f"{api_id} is missing from the device catalog")
    return violations, drift


def attest_device(
    device_catalog: object,
    *,
    device_catalog_revision: str | None,
    reference_catalog: Mapping[str, dict],
    tier_ceiling: str,
    catalog_revision: str,
) -> dict:
    """Full device attestation result per the control-plane contract."""
    tier_rank(tier_ceiling)  # fail closed on unknown ceiling before any comparison
    canonical = canonical_revision(dict(device_catalog))
    if device_catalog_revision is not None:
        if not isinstance(device_catalog_revision, str):
            raise CapabilityCatalogError("device_catalog_revision must be a string or null")
        if device_catalog_revision != canonical:
            raise CapabilityCatalogError(
                f"device_catalog_revision mismatch: declared {device_catalog_revision!r} "
                f"but catalog canonically hashes to {canonical}"
            )
    violations, drift = attest_device_catalog(
        device_catalog,
        reference_catalog=reference_catalog,
        tier_ceiling=tier_ceiling,
    )
    return {
        "attested": not violations and not drift,
        "violations": violations,
        "drift": drift,
        "catalog_revision": catalog_revision,
        "device_catalog_revision": canonical,
    }


STATION_REFERENCE_CATALOG: dict[str, dict] = {
    "android.wifi.read_connection_info.v1": {
        "api_id": "android.wifi.read_connection_info.v1",
        "adapter_id": "sdk_wifi_read_v1",
        "platform": "android",
        "min_api_level": 33,
        "max_api_level": None,
        "privilege_tier": "T1_APP",
        "required_permissions": ["android.permission.ACCESS_WIFI_STATE"],
        "hardware_features": ["android.hardware.wifi"],
        "argument_schema_revision": "1",
        "risk": "read_only",
        "device_status": "not_tested",
        "verification": {"test_id": None, "apk_sha256": None, "timestamp_utc": None},
    }
}