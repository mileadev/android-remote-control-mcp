"""Tests for the loopback-only JSON/HTTP control plane transport."""

from __future__ import annotations

import json
import socket
import threading
import unittest
import urllib.error
import urllib.request

from station.broker import BrokerStation
from station.http_api import StationControlPlane
from station.registry import CallerRegistry

from station.tests.support import (
    DEFAULT_TOKEN,
    DEVICES,
    FakeClock,
    SECOND_TOKEN,
    build_broker,
    build_registry,
    enroll_and_make_available,
    make_caller,
)


class HttpControlPlaneTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        registry, approval = build_registry()
        for spec in DEVICES.values():
            enroll_and_make_available(registry, approval, spec)
        self.broker, self.leasing = build_broker(self.clock, registry=registry)
        self.alice = make_caller(
            "alice", ("operator", "observer"), ("dev-pixel", "dev-second")
        )
        self.bob = make_caller("bob", ("observer",), ("dev-pixel",))
        self.callers = CallerRegistry()
        self.callers.register(token=DEFAULT_TOKEN, caller=self.alice)
        self.callers.register(token=SECOND_TOKEN, caller=self.bob)
        self.control = StationControlPlane(self.broker, caller_registry=self.callers)
        self._thread = threading.Thread(target=self.control.start, daemon=True)
        self._thread.start()
        self.base = f"http://{self.control.host}:{self.control.port}"

    def tearDown(self) -> None:
        self.control.stop()
        self._thread.join(timeout=5)

    # ------------------------------------------------------------ plumbing

    def _post(self, operation: str, body, *, token: str | None = DEFAULT_TOKEN, method: str = "POST"):
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body
        request = urllib.request.Request(
            f"{self.base}/v1/{operation}", data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as ex:
            return ex.code, json.loads(ex.read())

    def _acquire_lease(self, device_id: str = "dev-pixel") -> dict:
        status, body = self._post(
            "android.sessions.acquire", {"request_id": "http-acq", "device_id": device_id}
        )
        self.assertEqual(200, status, body)
        self.assertEqual("completed", body["status"])
        return {
            "lease_id": body["result"]["lease_id"],
            "lease_generation": body["result"]["lease_generation"],
        }

    # ---------------------------------------------------------------- tests

    def test_health_is_unauthenticated(self) -> None:
        with urllib.request.urlopen(f"{self.base}/health", timeout=5) as response:
            self.assertEqual(200, response.status)
            self.assertEqual({"status": "healthy"}, json.loads(response.read()))

    def test_post_executes_operation_with_bearer_identity(self) -> None:
        status, body = self._post(
            "android.devices.list", {"request_id": "http-list"}
        )
        self.assertEqual(200, status)
        self.assertEqual("completed", body["status"])
        self.assertEqual("alice", self.broker.audit_events()[-1]["caller"])
        self.assertIn("serial", body["result"]["devices"][0])

    def test_missing_or_invalid_token_is_401(self) -> None:
        status, body = self._post(
            "android.devices.list", {"request_id": "http-401"}, token=None
        )
        self.assertEqual(401, status)
        self.assertIn("identity", body["error"])
        status, _ = self._post(
            "android.devices.list", {"request_id": "http-401b"}, token="wrong-token"
        )
        self.assertEqual(401, status)

    def test_identity_comes_from_transport_not_envelope(self) -> None:
        forged = {
            "request_id": "http-forged",
            "arguments": {"caller_identity": "somebody-else"},
        }
        status, body = self._post("android.devices.list", forged)
        self.assertEqual(200, status)
        self.assertEqual("alice", self.broker.audit_events()[-1]["caller"])

    def test_unknown_route_is_404(self) -> None:
        status, _ = self._post("android.not.routed", {"request_id": "http-404"})
        self.assertEqual(404, status)
        try:
            urllib.request.urlopen(f"{self.base}/nowhere", timeout=5)
            self.fail("expected 404")
        except urllib.error.HTTPError as ex:
            self.assertEqual(404, ex.code)

    def test_wrong_method_is_405(self) -> None:
        status, _ = self._post(
            "android.devices.list", b"ignored", method="PUT"
        )
        self.assertEqual(405, status)

    def test_malformed_json_is_400(self) -> None:
        status, body = self._post(
            "android.devices.list", b"{definitely not json"
        )
        self.assertEqual(400, status)
        self.assertIn("JSON", body["error"])
        status, body = self._post("android.devices.list", b"[1, 2, 3]")
        self.assertEqual(400, status)
        self.assertIn("JSON object", body["error"])

    def test_broker_envelope_errors_map_to_400(self) -> None:
        status, body = self._post(
            "android.devices.list", {"request_id": "http-400", "bogus": 1}
        )
        self.assertEqual(400, status)
        self.assertIn("unknown envelope field", body["error"])

    def test_oversized_body_is_413(self) -> None:
        status, body = self._post(
            "android.devices.list",
            {"request_id": "http-413", "arguments": {"blob": "z" * 70000}},
        )
        self.assertEqual(413, status)
        self.assertIn("65536", body["error"])

    def test_negative_content_length_is_400(self) -> None:
        # A negative Content-Length used to reach self.rfile.read(-1), which blocks until the
        # peer closes, pinning the request thread for as long as the client keeps the socket.
        request = (
            f"POST /v1/android.devices.list HTTP/1.1\r\n"
            f"Host: {self.control.host}:{self.control.port}\r\n"
            f"Authorization: Bearer {DEFAULT_TOKEN}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: -1\r\n"
            f"\r\n"
        ).encode("utf-8")
        with socket.create_connection((self.control.host, self.control.port), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(request)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        raw = b"".join(chunks)
        self.assertIn(b"400", raw.split(b"\r\n", 1)[0], raw)
        self.assertIn(b"negative", raw)

    def test_unsupported_operations_return_200_unsupported_status(self) -> None:
        status, body = self._post(
            "android.video.session",
            {"request_id": "http-video", "device_id": "dev-pixel"},
            token=SECOND_TOKEN,
        )
        self.assertEqual(200, status)
        self.assertEqual("unsupported", body["status"])

    def test_full_acquire_observe_release_flow_over_http(self) -> None:
        lease = self._acquire_lease("dev-pixel")
        status, observe = self._post(
            "android.ui.observe",
            {
                "request_id": "http-observe",
                "device_id": "dev-pixel",
                "lease_id": lease["lease_id"],
                "lease_generation": lease["lease_generation"],
                "arguments": {},
                "idempotency_key": "http-observe-key",
            },
        )
        self.assertEqual(200, status, observe)
        self.assertEqual("completed", observe["status"])
        status, released = self._post(
            "android.sessions.release",
            {
                "request_id": "http-release",
                "device_id": "dev-pixel",
                "lease_id": lease["lease_id"],
                "lease_generation": lease["lease_generation"],
            },
        )
        self.assertEqual(200, status, released)
        self.assertEqual("completed", released["status"])
        self.assertTrue(released["result"]["released"])

    def test_non_loopback_bind_is_refused(self) -> None:
        for hostile in ("0.0.0.0", "10.1.2.3"):
            with self.assertRaises(ValueError):
                StationControlPlane(self.broker, caller_registry=self.callers, host=hostile)


if __name__ == "__main__":
    unittest.main()
