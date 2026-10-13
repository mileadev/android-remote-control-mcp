"""Loopback-only JSON/HTTP transport for the broker control plane.

Endpoints:

* ``GET  /health`` — unauthenticated liveness probe (no device data).
* ``POST /v1/<operation_id>`` — executes one control-plane operation.

Identity comes exclusively from the ``Authorization: Bearer <token>`` header
(resolved through station-side credentials) — never from the request body.
The listener refuses to start on any non-loopback address, which enforces
``control_plane.expose_public_http: false`` mechanically.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from station.broker import BrokerError, BrokerStation
from station.lab_policy import KNOWN_OPERATIONS, LOOPBACK_ADDRESSES
from station.registry import Caller, CallerRegistry

MAX_BODY_BYTES = 65536
JsonResolver = Callable[[str], "Caller | None"]


def bearer_identity_resolver(callers: CallerRegistry) -> JsonResolver:
    """Default resolver: map the presented bearer token to a station Caller."""

    def resolve(token: str) -> Caller | None:
        return callers.resolve(token)

    return resolve


class _Handler(BaseHTTPRequestHandler):
    broker: BrokerStation
    resolver: JsonResolver

    # --------------------------------------------------------------- helpers

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args) -> None:
        # Quiet by default: audit must not leak request material into logs.
        pass

    # ------------------------------------------------------------ dispatch

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "healthy"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        parts = self.path.split("/", 2)
        if len(parts) != 3 or parts[1] != "v1" or not parts[2]:
            self._send_json(404, {"error": "not found"})
            return
        operation_id = parts[2]
        expected = operation_id in KNOWN_OPERATIONS
        if not expected:
            self._send_json(404, {"error": "unknown operation route"})
            return
        caller = self._authenticate()
        if caller is None:
            self._send_json(401, {"error": "missing or invalid bearer identity"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "invalid Content-Length"})
            return
        if length < 0:
            self._send_json(400, {"error": "invalid Content-Length: must not be negative"})
            return
        if length > MAX_BODY_BYTES:
            self._send_json(413, {"error": f"request body exceeds {MAX_BODY_BYTES} bytes"})
            return
        body = self.rfile.read(length) if length else b""
        try:
            envelope = json.loads(body.decode("utf-8")) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "request body must be valid JSON"})
            return
        if not isinstance(envelope, dict):
            self._send_json(400, {"error": "request body must be a JSON object"})
            return
        try:
            response = self.broker.execute(caller, operation_id, envelope)
        except BrokerError as ex:
            self._send_json(400, {"error": str(ex)})
            return
        self._send_json(200, response)

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._send_json(405, {"error": "method not allowed"})

    def _authenticate(self) -> Caller | None:
        header = self.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme != "Bearer" or not token:
            return None
        return self.resolver(token)


class StationControlPlane:
    """Threading HTTP server exposing the broker on loopback only."""

    def __init__(
        self,
        broker: BrokerStation,
        *,
        identity_resolver: JsonResolver | None = None,
        caller_registry: CallerRegistry | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        if host not in LOOPBACK_ADDRESSES:
            raise ValueError(
                "control plane must bind a loopback address; exposing it publicly "
                "is forbidden by station policy"
            )
        if identity_resolver is not None and caller_registry is not None:
            raise ValueError("pass identity_resolver or caller_registry, not both")
        if caller_registry is not None:
            identity_resolver = bearer_identity_resolver(caller_registry)
        if identity_resolver is None:
            raise ValueError("an identity resolver (or caller registry) is required")

        class BoundHandler(_Handler):
            pass

        BoundHandler.broker = broker
        BoundHandler.resolver = staticmethod(identity_resolver)
        self._broker = broker
        self._serving = False
        self.server = ThreadingHTTPServer((host, port), BoundHandler)
        self.server.daemon_threads = True

    # ------------------------------------------------------------- plumbing

    @property
    def host(self) -> str:
        return self.server.server_address[0]

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def start(self) -> None:
        if not self._serving:
            self._serving = True
            self.server.serve_forever(poll_interval=0.05)

    def stop(self) -> None:
        self._serving = False
        self.server.shutdown()
        self.server.server_close()

    def serve(self) -> None:
        """Run the control plane in the current thread (production entrypoint)."""
        self._serving = True
        self.server.serve_forever(poll_interval=0.05)