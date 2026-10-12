"""Lab policy loader: strictly validated YAML subset, fail closed.

Parses the small deterministic YAML dialect used by
``station/config/lab-policy.example.yaml`` (nested mappings whose values are
booleans, integers, quoted or bare strings, and flat lists of strings) and
validates every security-relevant invariant before returning a policy.

Anything unexpected (tabs, unknown keys, unknown schema version, unsafe
values, wrong types, duplicates, mixed containers) raises ``PolicyError``.
A YAML file by itself enforces nothing; code must always call ``load_lab_policy``
and act on the resulting typed policy.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "station-policy-1"
MODE = "deny_by_default"

KNOWN_OPERATIONS = frozenset(
    {
        "android.devices.list",
        "android.devices.capabilities",
        "android.sessions.acquire",
        "android.sessions.renew",
        "android.sessions.release",
        "android.ui.observe",
        "android.ui.batch",
        "android.ui.wait",
        "android.api.describe",
        "android.api.invoke_typed",
        "android.tests.submit",
        "android.tests.status",
        "android.video.session",
        "android.logs.query",
    }
)

MANDATORY_FORBIDDEN = frozenset(
    {
        "raw_adb_shell",
        "raw_reflection",
        "arbitrary_code",
        "flash",
        "root",
        "unknown_download_url",
    }
)

_FORBIDDEN_ADB_PORTS = frozenset({5037, 5555})
_LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1", "localhost"})
_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_INT_PATTERN = re.compile(r"^[+-]?[0-9]+$")
_TOOL_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_OPERATION_ID_PATTERN = re.compile(r"^android\.[a-z][a-z0-9_.]{1,63}$")

FORBIDDEN_ADB_PORTS = _FORBIDDEN_ADB_PORTS
LOOPBACK_ADDRESSES = _LOOPBACK_ADDRESSES


class PolicyError(ValueError):
    """Raised for any policy parse or validation failure (fail closed)."""


@dataclass(frozen=True)
class ControlPlanePolicy:
    expose_public_http: bool
    transport: str
    require_oidc_identity: bool
    audit_timestamp_format: str


@dataclass(frozen=True)
class SessionPolicy:
    exclusive_device_lease: bool
    require_station_fencing_generation: bool
    lease_ttl_seconds: int
    heartbeat_seconds: int
    deny_on_backend_unavailable: bool
    idempotency_ttl_seconds: int


@dataclass(frozen=True)
class DeviceEnrollmentPolicy:
    explicit_serial_allowlist: bool
    allow_mdns_autoconnect: bool
    allow_adb_tcp_public: bool
    allow_root_on_stock_devices: bool


@dataclass(frozen=True)
class NativeMcpPolicy:
    device_bind_address: str
    device_port: int
    require_auth: bool
    allow_dual_auth_disabled: bool
    allow_any_origin: bool
    require_allowlisted_host: bool
    enable_public_tunnels: bool
    enable_http_download: bool
    allow_unverified_https_certs: bool
    allowed_tool_ids: tuple[str, ...]


@dataclass(frozen=True)
class StationPolicy:
    allowed_operations: tuple[str, ...]
    never_expose_to_llm: tuple[str, ...]
    release_on_lease_expiry: bool
    reject_ats_owned_devices: bool


@dataclass(frozen=True)
class LoggingPolicy:
    log_payloads: bool
    log_secrets: bool
    log_ui_content_by_default: bool
    record_request_id: bool


@dataclass(frozen=True)
class PrivilegedPoolPolicy:
    enabled: bool
    requires_operator_approval: bool


@dataclass(frozen=True)
class LabPolicy:
    schema_version: str
    mode: str
    control_plane: ControlPlanePolicy
    session: SessionPolicy
    device_enrollment: DeviceEnrollmentPolicy
    native_mcp: NativeMcpPolicy
    station: StationPolicy
    logging: LoggingPolicy
    privileged_pool: PrivilegedPoolPolicy
    config_digest: str = ""

    @property
    def digest(self) -> str:
        return self.config_digest or "sha256:" + hashlib.sha256(b"").hexdigest()


def _fail(message: str) -> None:
    raise PolicyError(message)


def _strip_comment(line: str) -> str:
    in_single = in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            if index == 0 or line[index - 1] in " \t":
                return line[:index].rstrip()
    return line.rstrip()


def _scalar(text: str, where: str):
    value = text.strip()
    if not value:
        _fail(f"{where}: empty value")
    if value[0] in "\"'":
        quote = value[0]
        if len(value) < 2 or not value.endswith(quote) or quote in value[1:-1]:
            _fail(f"{where}: malformed quoted scalar")
        inner = value[1:-1]
        if inner == "":
            _fail(f"{where}: empty quoted scalar")
        return inner
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in ("null", "~"):
        return None
    if _INT_PATTERN.fullmatch(value):
        return int(value)
    if ": " in value or value.endswith(":"):
        _fail(f"{where}: ambiguous scalar contains a key separator")
    if not _KEY_PATTERN.fullmatch(value):
        _fail(f"{where}: scalar has unsupported characters: {value!r}")
    return value


def _split_key(text: str, where: str) -> tuple[str, str]:
    colon = text.find(":")
    if colon <= 0:
        _fail(f"{where}: line is not a valid mapping entry: {text!r}")
    key = text[:colon].strip()
    rest = text[colon + 1 :].strip()
    if colon + 1 < len(text) and text[colon + 1] not in (" ", ""):
        _fail(f"{where}: expected 'key: value' syntax")
    if not _KEY_PATTERN.fullmatch(key):
        _fail(f"{where}: invalid key {key!r}")
    return key, rest


def _preprocess(text: str) -> list[tuple[int, str]]:
    if not text or not text.strip():
        _fail("policy document is empty")
    if "\t" in text:
        _fail("policy document contains tab characters")
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if raw != raw.rstrip("\r"):
            raw = raw.rstrip("\r")
        stripped = _strip_comment(raw)
        if not stripped.strip() or stripped.strip().startswith("#"):
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        if indent % 2 != 0:
            _fail(f"indentation must be an even number of spaces: {stripped!r}")
        lines.append((indent, stripped.strip()))
    if not lines:
        _fail("policy document has no content")
    if lines[0][0] != 0:
        _fail("first mapping key must start at column 0")
    return lines


def _parse_block(lines: list[tuple[int, str]], pos: int, indent: int):
    first = lines[pos][1]
    if first.startswith("- "):
        sequence: list = []
        index = pos
        while index < len(lines):
            line_indent, text = lines[index]
            if line_indent < indent:
                break
            if line_indent > indent:
                _fail(f"unexpected extra indentation in list: {text!r}")
            if not text.startswith("- "):
                break
            sequence.append(_scalar(text[2:], "list item"))
            index += 1
        return sequence, index

    mapping: dict = {}
    index = pos
    while index < len(lines):
        line_indent, text = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            _fail(f"unexpected extra indentation: {text!r}")
        if text.startswith("- "):
            _fail("mixed mapping and list entries are not allowed")
        key, rest = _split_key(text, "mapping")
        if key in mapping:
            _fail(f"duplicate key {key!r}")
        if rest == "":
            if index + 1 < len(lines) and lines[index + 1][0] > line_indent:
                block, parsed_to = _parse_block(lines, index + 1, lines[index + 1][0])
                mapping[key] = block
                index = parsed_to
                continue
            _fail(f"key {key!r} has no value and no nested block")
        mapping[key] = _scalar(rest, f"key {key!r}")
        index += 1
    return mapping, index


def _parse_document(text: str) -> dict:
    lines = _preprocess(text)
    document, parsed_to = _parse_block(lines, 0, 0)
    if parsed_to != len(lines):
        _fail("trailing content after top-level mapping")
    if not isinstance(document, dict):
        _fail("top-level document must be a mapping")
    return document


def _section(document: dict, name: str) -> dict:
    if name not in document:
        _fail(f"missing required section: {name}")
    section = document[name]
    if not isinstance(section, dict):
        _fail(f"section {name} must be a mapping")
    return section


def _keys(section: dict, name: str, required: frozenset[str]) -> None:
    for key in section:
        if key not in required:
            _fail(f"unknown key {key!r} in section {name}")
    for key in required:
        if key not in section:
            _fail(f"missing key {key!r} in section {name}")


def _bool_key(section: dict, name: str, key: str, expected: bool) -> bool:
    value = section[key]
    if not isinstance(value, bool):
        _fail(f"{name}.{key} must be a boolean")
    if value is not expected:
        _fail(f"{name}.{key} must be {str(expected).lower()}")
    return value


def _bool_value(section: dict, name: str, key: str) -> bool:
    value = section[key]
    if not isinstance(value, bool):
        _fail(f"{name}.{key} must be a boolean")
    return value


def _string_choice(section: dict, name: str, key: str, choices: frozenset[str]) -> str:
    value = section[key]
    if not isinstance(value, str) or value not in choices:
        _fail(f"{name}.{key} must be one of {sorted(choices)}")
    return value


def _int_in_range(section: dict, name: str, key: str, low: int, high: int) -> int:
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{name}.{key} must be an integer")
    if not low <= value <= high:
        _fail(f"{name}.{key} must be between {low} and {high}")
    return value


def _string_list(section: dict, name: str, key: str) -> tuple[str, ...]:
    value = section[key]
    if not isinstance(value, list) or not value:
        _fail(f"{name}.{key} must be a non-empty list")
    for item in value:
        if not isinstance(item, str) or not item:
            _fail(f"{name}.{key} items must be non-empty strings")
    return tuple(value)


def _validate(document: dict, text: str) -> LabPolicy:
    allowed_top = frozenset(
        {
            "schema_version",
            "mode",
            "control_plane",
            "session",
            "device_enrollment",
            "native_mcp",
            "station",
            "logging",
            "privileged_pool",
        }
    )
    for key in document:
        if key not in allowed_top:
            _fail(f"unknown top-level key {key!r}")

    if document.get("schema_version") != SCHEMA_VERSION:
        _fail(f"schema_version must be {SCHEMA_VERSION!r}")
    if document.get("mode") != MODE:
        _fail(f"mode must be {MODE!r}")

    control = _section(document, "control_plane")
    _keys(
        control,
        "control_plane",
        frozenset(
            {
                "expose_public_http",
                "transport",
                "require_oidc_identity",
                "audit_timestamp_format",
            }
        ),
    )
    control_plane = ControlPlanePolicy(
        expose_public_http=_bool_key(control, "control_plane", "expose_public_http", False),
        transport=_string_choice(control, "control_plane", "transport", frozenset({"mtls_private"})),
        require_oidc_identity=_bool_key(control, "control_plane", "require_oidc_identity", True),
        audit_timestamp_format=_string_choice(
            control, "control_plane", "audit_timestamp_format", frozenset({"iso8601_utc"})
        ),
    )

    session = _section(document, "session")
    _keys(
        session,
        "session",
        frozenset(
            {
                "exclusive_device_lease",
                "require_station_fencing_generation",
                "lease_ttl_seconds",
                "heartbeat_seconds",
                "deny_on_backend_unavailable",
                "idempotency_ttl_seconds",
            }
        ),
    )
    exclusive = _bool_key(session, "session", "exclusive_device_lease", True)
    fencing = _bool_key(session, "session", "require_station_fencing_generation", True)
    ttl = _int_in_range(session, "session", "lease_ttl_seconds", 10, 3600)
    heartbeat = _int_in_range(session, "session", "heartbeat_seconds", 1, ttl)
    deny_backend = _bool_key(session, "session", "deny_on_backend_unavailable", True)
    idem_ttl = _int_in_range(session, "session", "idempotency_ttl_seconds", 30, 86400)
    if heartbeat > ttl:
        _fail("session.heartbeat_seconds must not exceed lease_ttl_seconds")
    session_policy = SessionPolicy(
        exclusive_device_lease=exclusive,
        require_station_fencing_generation=fencing,
        lease_ttl_seconds=ttl,
        heartbeat_seconds=heartbeat,
        deny_on_backend_unavailable=deny_backend,
        idempotency_ttl_seconds=idem_ttl,
    )

    enrollment = _section(document, "device_enrollment")
    _keys(
        enrollment,
        "device_enrollment",
        frozenset(
            {
                "explicit_serial_allowlist",
                "allow_mdns_autoconnect",
                "allow_adb_tcp_public",
                "allow_root_on_stock_devices",
            }
        ),
    )
    enrollment_policy = DeviceEnrollmentPolicy(
        explicit_serial_allowlist=_bool_key(
            enrollment, "device_enrollment", "explicit_serial_allowlist", True
        ),
        allow_mdns_autoconnect=_bool_key(
            enrollment, "device_enrollment", "allow_mdns_autoconnect", False
        ),
        allow_adb_tcp_public=_bool_key(
            enrollment, "device_enrollment", "allow_adb_tcp_public", False
        ),
        allow_root_on_stock_devices=_bool_key(
            enrollment, "device_enrollment", "allow_root_on_stock_devices", False
        ),
    )

    native = _section(document, "native_mcp")
    native_fields = frozenset(
        {
            "device_bind_address",
            "device_port",
            "require_auth",
            "allow_dual_auth_disabled",
            "allow_any_origin",
            "require_allowlisted_host",
            "enable_public_tunnels",
            "enable_http_download",
            "allow_unverified_https_certs",
            "allowed_tool_ids",
        }
    )
    _keys(native, "native_mcp", native_fields)
    bind = native["device_bind_address"]
    if not isinstance(bind, str) or bind not in _LOOPBACK_ADDRESSES:
        _fail("native_mcp.device_bind_address must be a loopback address")
    port = _int_in_range(native, "native_mcp", "device_port", 1, 65535)
    if port in _FORBIDDEN_ADB_PORTS:
        _fail("native_mcp.device_port must not be ADB port 5037 or 5555")
    tool_ids = _string_list(native, "native_mcp", "allowed_tool_ids")
    for tool_id in tool_ids:
        if not _TOOL_ID_PATTERN.fullmatch(tool_id):
            _fail(f"native_mcp.allowed_tool_ids entry is not a tool id: {tool_id!r}")
    native_policy = NativeMcpPolicy(
        device_bind_address=bind,
        device_port=port,
        require_auth=_bool_key(native, "native_mcp", "require_auth", True),
        allow_dual_auth_disabled=_bool_key(native, "native_mcp", "allow_dual_auth_disabled", False),
        allow_any_origin=_bool_key(native, "native_mcp", "allow_any_origin", False),
        require_allowlisted_host=_bool_key(native, "native_mcp", "require_allowlisted_host", True),
        enable_public_tunnels=_bool_key(native, "native_mcp", "enable_public_tunnels", False),
        enable_http_download=_bool_key(native, "native_mcp", "enable_http_download", False),
        allow_unverified_https_certs=_bool_key(
            native, "native_mcp", "allow_unverified_https_certs", False
        ),
        allowed_tool_ids=tool_ids,
    )

    station = _section(document, "station")
    _keys(
        station,
        "station",
        frozenset(
            {
                "allowed_operations",
                "never_expose_to_llm",
                "release_on_lease_expiry",
                "reject_ats_owned_devices",
            }
        ),
    )
    allowed = _string_list(station, "station", "allowed_operations")
    forbidden = _string_list(station, "station", "never_expose_to_llm")
    for operation_id in allowed:
        if not _OPERATION_ID_PATTERN.fullmatch(operation_id) or operation_id not in KNOWN_OPERATIONS:
            _fail(f"station.allowed_operations contains an unknown operation: {operation_id!r}")
    missing_forbidden = MANDATORY_FORBIDDEN.difference(forbidden)
    if missing_forbidden:
        _fail(f"station.never_expose_to_llm must include {sorted(missing_forbidden)}")
    overlap = frozenset(allowed).intersection(forbidden)
    if overlap:
        _fail(f"allowed operations must not be in never_expose_to_llm: {sorted(overlap)}")
    station_policy = StationPolicy(
        allowed_operations=tuple(sorted(allowed)),
        never_expose_to_llm=tuple(sorted(set(forbidden))),
        release_on_lease_expiry=_bool_key(station, "station", "release_on_lease_expiry", True),
        reject_ats_owned_devices=_bool_key(station, "station", "reject_ats_owned_devices", True),
    )

    logging = _section(document, "logging")
    _keys(
        logging,
        "logging",
        frozenset(
            {
                "log_payloads",
                "log_secrets",
                "log_ui_content_by_default",
                "record_request_id",
            }
        ),
    )
    logging_policy = LoggingPolicy(
        log_payloads=_bool_key(logging, "logging", "log_payloads", False),
        log_secrets=_bool_key(logging, "logging", "log_secrets", False),
        log_ui_content_by_default=_bool_key(
            logging, "logging", "log_ui_content_by_default", False
        ),
        record_request_id=_bool_key(logging, "logging", "record_request_id", True),
    )

    privileged = _section(document, "privileged_pool")
    _keys(
        privileged,
        "privileged_pool",
        frozenset({"enabled", "requires_operator_approval"}),
    )
    privileged_policy = PrivilegedPoolPolicy(
        enabled=_bool_value(privileged, "privileged_pool", "enabled"),
        requires_operator_approval=_bool_key(
            privileged, "privileged_pool", "requires_operator_approval", True
        ),
    )

    return LabPolicy(
        schema_version=document["schema_version"],
        mode=document["mode"],
        control_plane=control_plane,
        session=session_policy,
        device_enrollment=enrollment_policy,
        native_mcp=native_policy,
        station=station_policy,
        logging=logging_policy,
        privileged_pool=privileged_policy,
        config_digest="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )


def load_lab_policy(text: str) -> LabPolicy:
    """Parse and validate raw policy text. Raises ``PolicyError`` on any doubt."""
    if not isinstance(text, str):
        _fail("policy text must be a string")
    return _validate(_parse_document(text), text)


def load_lab_policy_file(path: str | Path) -> LabPolicy:
    """Load and validate a policy file from disk."""
    data = Path(path).read_text(encoding="utf-8")
    return load_lab_policy(data)


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent / "config" / "lab-policy.example.yaml"


def utc_timestamp(now: datetime | None = None) -> str:
    value = now or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")