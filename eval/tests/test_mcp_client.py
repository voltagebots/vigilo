import socket
from datetime import UTC, datetime, timedelta

import pytest

from harness.mcp_client import VigiloMCPClient

MCP_URL = "http://127.0.0.1:7070"


def _daemon_reachable() -> bool:
    # SSE endpoints hang waiting to stream rather than responding to a plain
    # GET -- a raw TCP connect is the right reachability check here, not an
    # HTTP request against the streaming endpoint itself.
    try:
        with socket.create_connection(("127.0.0.1", 7070), timeout=1.0):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _daemon_reachable(), reason="no vigilo daemon running at localhost:7070")
def test_get_all_events_returns_real_events():
    client = VigiloMCPClient(MCP_URL)
    since = (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events = client.get_all_events(since)
    assert isinstance(events, list)


@pytest.mark.skipif(not _daemon_reachable(), reason="no vigilo daemon running at localhost:7070")
def test_find_matching_event_no_match_returns_none():
    from harness.mcp_client import DaemonEvent

    client = VigiloMCPClient(MCP_URL)
    events = [DaemonEvent(source="file", action="write", resource="/app/keystore/x", severity="critical", timestamp="")]
    assert client.find_matching_event("/nonexistent/path", events) is None
