"""Captures Vigilo's immediate-tier alerts. Runs two ways: as the
containerized listener (docker/Dockerfile.listener, reachable by the daemon
at http://webhook-listener:8090/alert per config.eval.yaml) and imported
directly in unit tests without a container.

t1 is the arrival wall-clock time recorded here, in the SAME clock domain as
trigger.py's t0 when both run inside the eval network -- never the webhook
payload's own `timestamp` field, which mem0's... no, Vigilo's webhook.go
formats with time.RFC3339 (whole-second precision), unusable for a ~1s
latency claim (Step 0.5 H3)."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass(frozen=True)
class AlertReceived:
    t1: float  # time.time() at arrival -- the actual latency signal, not the payload's timestamp
    payload: dict


class WebhookListener:
    def __init__(self, host: str = "0.0.0.0", port: int = 8090) -> None:
        self._host = host
        self._port = port
        self._alerts: list[AlertReceived] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def _record(self, payload: dict) -> None:
        with self._lock:
            self._alerts.append(AlertReceived(t1=time.time(), payload=payload))

    def start(self) -> None:
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    # Malformed payload must not crash the listener or lose the
                    # timestamp signal -- log the raw body, still record arrival.
                    payload = {"_malformed_raw_body": body.decode("utf-8", errors="replace")}
                listener._record(payload)
                self.send_response(200)
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/alerts":
                    self.send_response(404)
                    self.end_headers()
                    return
                with listener._lock:
                    body = json.dumps(
                        [{"t1": a.t1, "payload": a.payload} for a in listener._alerts]
                    ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:  # noqa: A002
                pass  # keep test/eval output quiet, not silent-swallowing errors

        self._server = ThreadingHTTPServer((self._host, self._port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def get_alerts(self) -> list[AlertReceived]:
        with self._lock:
            return list(self._alerts)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
