"""Station-side ADB access control: read-only inventory allowlist.

Ported from the handoff's ``android_capability_probe.py`` and hardened:

* Serials must be explicitly allowlisted (enrolled) in the station registry;
  auto-selection, wildcards, and mDNS discovery are refused.
* Only a fixed set of read-only commands is permitted. There is no path to
  ``adb tcpip``, ``adb root``, installs, or arbitrary shell input.
* No port forwarding: this module never builds, exposes, or bookkeeps an ADB
  forward slot.
* All subprocess execution uses ``shell=False`` with an argv list; timeouts are
   bounded to 1..30 seconds.
"""

from __future__ import annotations

import re
import subprocess
from typing import Callable

from station.registry import DeviceRegistry, SERIAL_PATTERN

PROP_KEYS = (
    "ro.build.version.sdk",
    "ro.build.version.release",
    "ro.build.type",
    "ro.debuggable",
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.build.fingerprint",
)

ADDITIONAL = (
    ("identity", ("shell", "id")),
    ("hardware_features", ("shell", "pm", "list", "features")),
    ("command_services", ("shell", "cmd", "-l")),
    ("binder_services", ("shell", "service", "list")),
)

RunFn = Callable[[list[str], int], tuple[int, str, str]]


class AdbPolicyError(RuntimeError):
    """Fail-closed ADB access violation (never falls back to execution)."""


def default_run(argv: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            shell=False,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"command timed out after {timeout}s"
    except OSError as ex:
        return 127, "", str(ex)
    return result.returncode, result.stdout, result.stderr


def parse_devices(stdout: str) -> dict[str, str]:
    devices: dict[str, str] = {}
    states = {"device", "offline", "unauthorized", "recovery", "sideload", "bootloader"}
    for line in stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] != "List" and parts[1] in states:
            devices[parts[0]] = parts[1]
    return devices


def parse_features(stdout: str) -> list[str]:
    values = {
        line.removeprefix("feature:").strip()
        for line in stdout.splitlines()
        if line.startswith("feature:")
    }
    return sorted(values)


def parse_binder_services(stdout: str) -> list[str]:
    names = []
    for line in stdout.splitlines():
        match = re.match(r"^\s*\d+\s+([^:\s]+):", line)
        if match:
            names.append(match.group(1))
    return sorted(set(names))


def parse_command_services(stdout: str) -> list[str]:
    names = []
    for line in stdout.splitlines():
        line = line.strip()
        if line and line != "Currently running services:" and re.fullmatch(r"[\w.-]+", line):
            names.append(line)
    return sorted(set(names))


class AdbCommandPolicy:
    """Deterministic builder of allowlisted, read-only ADB argv vectors."""

    _GETPROP_COMMAND = ("shell", "getprop")
    _READ_ONLY_SHELL_COMMANDS = (
        ("shell", "id"),
        ("shell", "pm", "list", "features"),
        ("shell", "cmd", "-l"),
        ("shell", "service", "list"),
    )

    def __init__(self, registry: DeviceRegistry, *, adb_binary: str = "adb") -> None:
        if not adb_binary or adb_binary.startswith("-"):
            raise ValueError("adb_binary must be a plain program name or path")
        self._registry = registry
        self._adb_binary = adb_binary

    def require_enrolled_serial(self, serial: str) -> None:
        if not isinstance(serial, str) or not serial:
            raise AdbPolicyError("a serial is required: use adb devices -l to copy it exactly")
        if not SERIAL_PATTERN.fullmatch(serial):
            raise AdbPolicyError("serial contains invalid characters; use adb devices -l to copy it exactly")
        if serial.startswith("-"):
            raise AdbPolicyError("serial must not start with '-'")
        try:
            self._registry.get_by_serial(serial)
        except Exception as ex:
            raise AdbPolicyError(f"serial {serial!r} is not enrolled on this station: {ex}") from ex

    def command_argv(self, serial: str, args: tuple[str, ...] | list[str]) -> list[str]:
        """Return the exact argv for one allowlisted read-only ADB command."""
        self.require_enrolled_serial(serial)
        argv = [self._adb_binary, "-s", serial]
        argv.extend(self._validate_args(args))
        return argv

    def devices_argv(self) -> list[str]:
        return [self._adb_binary, "devices", "-l"]

    def _validate_args(self, args: tuple[str, ...] | list[str]) -> list[str]:
        if not args:
            raise AdbPolicyError("an ADB command is required")
        for arg in args:
            if not isinstance(arg, str) or not arg:
                raise AdbPolicyError("every ADB argument must be a non-empty string")
        if args[0] != "shell":
            raise AdbPolicyError(f"ADB command {args[0]!r} is not allowlisted")
        return self._validate_shell_args(args)

    def _validate_shell_args(self, args: tuple[str, ...] | list[str]) -> list[str]:
        if len(args) == 3 and args[:2] == self._GETPROP_COMMAND and args[2] in PROP_KEYS:
            return list(args)
        for command in self._READ_ONLY_SHELL_COMMANDS:
            if tuple(args) == command:
                return list(args)
        raise AdbPolicyError(f"ADB shell command {tuple(args)!r} is not allowlisted")


def collect_inventory(
    serial: str,
    policy: AdbCommandPolicy,
    *,
    runner: RunFn = default_run,
    timeout: int = 8,
) -> dict:
    """Run the read-only inventory for one enrolled serial and return raw output."""
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
        raise ValueError("Timeout must be between 1 and 30 seconds")
    policy.require_enrolled_serial(serial)

    rc, stdout, stderr = runner(policy.devices_argv(), timeout)
    if rc != 0:
        raise RuntimeError(f"adb devices failed (code {rc}): {stderr[:200]}")
    listed = parse_devices(stdout)
    if serial not in listed:
        raise RuntimeError(
            f"Refusing unlisted serial; selected={serial!r}, known_devices={len(listed)}"
        )
    if listed[serial] != "device":
        raise RuntimeError(f"Device is not in authorized online state: {listed[serial]!r}")

    props: dict[str, str | None] = {}
    errors: dict[str, str] = {}
    for key in PROP_KEYS:
        value, err = _query(policy.command_argv(serial, ("shell", "getprop", key)), runner, timeout)
        props[key] = value
        if err:
            errors[key] = err

    extras: dict[str, str | None] = {}
    for key, args in ADDITIONAL:
        value, err = _query(policy.command_argv(serial, args), runner, timeout)
        extras[key] = value
        if err:
            errors[key] = err

    identity = extras.get("identity")
    features_raw = extras.get("hardware_features")
    command_raw = extras.get("command_services")
    binder_raw = extras.get("binder_services")
    return {
        "serial": serial,
        "adb_state": listed[serial],
        "props": props,
        "hardware_features": parse_features(features_raw) if isinstance(features_raw, str) else [],
        "command_services": parse_command_services(command_raw) if isinstance(command_raw, str) else [],
        "binder_services": parse_binder_services(binder_raw) if isinstance(binder_raw, str) else [],
        "identity": identity,
        "errors": errors,
    }


def _query(argv: list[str], runner: RunFn, timeout: int) -> tuple[str | None, str | None]:
    code, out, err = runner(argv, timeout)
    if code != 0:
        return None, f"status {code}: {err[:160].strip() or 'query unsupported'}"
    return out.strip(), None
