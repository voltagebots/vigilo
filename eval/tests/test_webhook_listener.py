import json
import socket
import urllib.request

import pytest

from harness.webhook_listener import DecoyListener, WebhookListener


@pytest.fixture
def listener():
    listener = WebhookListener(host="127.0.0.1", port=0)
    listener._port = 18099  # fixed test port, avoid OS ephemeral-port complexity for a fixture
    listener.start()
    yield listener
    listener.stop()


def test_captures_a_real_post(listener):
    payload = {"source": "file", "action": "read", "resource": "/app/keystore", "severity": "high"}
    req = urllib.request.Request(
        "http://127.0.0.1:18099/alert", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=2.0)

    alerts = listener.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].payload == payload


def test_malformed_payload_does_not_crash_listener(listener):
    req = urllib.request.Request("http://127.0.0.1:18099/alert", data=b"not json{{{")
    urllib.request.urlopen(req, timeout=2.0)  # must not raise on the client side either

    alerts = listener.get_alerts()
    assert len(alerts) == 1
    assert "_malformed_raw_body" in alerts[0].payload

    # listener must still be alive for a subsequent real request
    payload2 = {"source": "network", "action": "connect", "resource": "1.2.3.4:9001", "severity": "high"}
    req2 = urllib.request.Request("http://127.0.0.1:18099/alert", data=json.dumps(payload2).encode())
    urllib.request.urlopen(req2, timeout=2.0)
    assert len(listener.get_alerts()) == 2


def test_t1_is_arrival_time_not_payload_timestamp(listener):
    stale_payload_timestamp = "2020-01-01T00:00:00Z"
    payload = {"timestamp": stale_payload_timestamp, "action": "read"}
    req = urllib.request.Request("http://127.0.0.1:18099/alert", data=json.dumps(payload).encode())
    import time

    before = time.time()
    urllib.request.urlopen(req, timeout=2.0)
    after = time.time()

    alert = listener.get_alerts()[0]
    assert before <= alert.t1 <= after


def test_decoy_listener_accepts_and_holds_a_real_connection():
    decoy = DecoyListener(host="127.0.0.1", port=18444)
    decoy.start()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", 18444))
        # connection must not be immediately reset -- a brief lack of RST/error
        # is the whole point (keeps the connection ESTABLISHED for a poller)
        s.settimeout(0.3)
        with pytest.raises(socket.timeout):
            s.recv(1)
        s.close()
    finally:
        decoy.stop()
