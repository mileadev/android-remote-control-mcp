"""Device driver layer: the station talks to device adapters over loopback only.

``DeviceDriver`` is the seam the broker codes against. ``RecordingDeviceDriver``
is a deterministic test double (fake clock friendly, no sleeps). The only
network transport shipped is ``LoopbackJsonRpcDriver``, which refuses any
non-loopback host per the control-plane contract.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from station.lab_policy import LOOPBACK_ADDRESSES

DRIVER_TIMEOUT_STATUS = 124


class DriverError(RuntimeError):
    """Driver failed to execute the operation (device-side failure)."""


class DriverTimeout(DriverError):
    """Driver did not answer within the deadline; operation outcome unknown."""


@dataclass(frozen=True)
class DriverResponse:
    status: str
    result: dict | None = None
    tree_generation: int | None = None
    error: str | None = None


class DeviceDriver(ABC):
    @abstractmethod
    def perform(
        self,
        device_id: str,
        operation_id: str,
        arguments: dict,
        timeout_seconds: float,
    ) -> DriverResponse:
        raise NotImplementedError


PerformHook = Callable[[str, str, dict, float], None]


class RecordingDeviceDriver(DeviceDriver):
    """Deterministic driver double used by the unittest suites.

    * Records every call in ``calls`` (device_id, operation_id, arguments, timeout_seconds).
    * Returns ``responses[operation_id]`` if present, otherwise a completed response.
    * Raises ``DriverTimeout`` deterministically when ``simulated_duration_ms``
      exceeds the deadline; ``on_perform`` lets tests advance the fake clock
      mid-execution (e.g. to make a lease expire during a tap).
    """

    def __init__(
        self,
        responses: dict[str, DriverResponse] | None = None,
        *,
        simulated_duration_ms: float = 0.0,
        on_perform: PerformHook | None = None,
        fail_with: Exception | None = None,
    ) -> None:
        self.calls: list[tuple[str, str, dict, float]] = []
        self.responses = dict(responses or {})
        self.simulated_duration_ms = simulated_duration_ms
        self.on_perform = on_perform
        self.fail_with = fail_with

    def set_response(self, operation_id: str, response: DriverResponse) -> None:
        self.responses[operation_id] = response

    def perform(
        self,
        device_id: str,
        operation_id: str,
        arguments: dict,
        timeout_seconds: float,
    ) -> DriverResponse:
        self.calls.append((device_id, operation_id, dict(arguments), float(timeout_seconds)))
        if self.on_perform is not None:
            self.on_perform(device_id, operation_id, arguments, timeout_seconds)
        if self.fail_with is not None:
            raise self.fail_with if isinstance(self.fail_with, DriverError) else DriverError(str(self.fail_with))
        if self.simulated_duration_ms > timeout_seconds * 1000.0:
            raise DriverTimeout(
                f"driver did not answer {operation_id!r} within {timeout_seconds}s"
            )
        response = self.responses.get(operation_id)
        if response is not None:
            return response
        return DriverResponse(status="completed", result={"operation_id": operation_id}, tree_generation=None, error=None)


class LoopbackJsonRpcDriver(DeviceDriver):
    """Minimal JSON-over-HTTP client for a loopback-only device adapter."""

    def __init__(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("driver url must use http or https")
        host = parsed.hostname or ""
        if host not in LOOPBACK_ADDRESSES:
            raise ValueError("device adapters must be reachable on loopback only")
        if host == "::1":
            url = url.replace("::1", "[::1]", 1)
        self._url = url

    def perform(
        self,
        device_id: str,
        operation_id: str,
        arguments: dict,
        timeout_seconds: float,
    ) -> DriverResponse:
        payload = json.dumps(
            {
                "device_id": device_id,
                "operation_id": operation_id,
                "arguments": arguments,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as ex:
            raise DriverError(f"adapter responded with HTTP {ex.code}") from ex
        except urllib.error.URLError as ex:
            raise DriverTimeout(f"adapter unreachable within {timeout_seconds}s: {ex.reason}") from ex
        except TimeoutError as ex:
            raise DriverTimeout(f"adapter did not answer within {timeout_seconds}s") from ex
        except (json.JSONDecodeError, UnicodeDecodeError) as ex:
            raise DriverError(f"adapter returned malformed JSON: {ex}") from ex
        if not isinstance(body, dict) or not isinstance(body.get("status"), str):
            raise DriverError("adapter response must be an object with a string 'status'")
        result = body.get("result")
        if result is not None and not isinstance(result, dict):
            raise DriverError("adapter 'result' must be an object")
        tree_generation = body.get("tree_generation")
        if tree_generation is not None and not isinstance(tree_generation, int):
            raise DriverError("adapter 'tree_generation' must be an integer or null")
        error = body.get("error")
        if error is not None and not isinstance(error, str):
            raise DriverError("adapter 'error' must be a string or null")
        return DriverResponse(
            status=body["status"],
            result=result,
            tree_generation=tree_generation,
            error=error,
        )