"""Real MCP client against Vigilo's own daemon -- the tool's own documented
read interface (README: "no log-scraping fallback"), not the SQLite buffer
directly. get_all_events/get_critical_events (verified against
internal/mcp/server.go directly, Step 0.5 M1 -- the tool set is NOT the
"list_recent_events" guessed in early planning, nor "5 tools" as the
README's own count claims; 6 real tools exist).

Cross-check only (Step 0.5 H3): the daemon's own event timestamps are
detection-time, not alert-arrival-time -- never averaged into a reported
latency number, only used to confirm a webhook-captured alert corresponds
to a real daemon-side detection."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from mcp import ClientSession
from mcp.client.sse import sse_client


@dataclass(frozen=True)
class DaemonEvent:
    source: str
    action: str
    resource: str
    severity: str
    timestamp: str


class VigiloMCPClient:
    def __init__(self, base_url: str) -> None:
        # server.ServeSSE (Go, server.NewSSEServer) exposes /sse by default.
        self._sse_url = base_url.rstrip("/") + "/sse"

    async def _call_tool(self, tool_name: str, since_rfc3339: str) -> list[DaemonEvent]:
        async with sse_client(self._sse_url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, {"since": since_rfc3339})
                text = result.content[0].text if result.content else "[]"
                rows = json.loads(text)
                if isinstance(rows, dict) and "error" in rows:
                    raise RuntimeError(f"MCP tool {tool_name!r} returned an error: {rows['error']}")
                return [
                    DaemonEvent(
                        source=r.get("source", ""),
                        action=r.get("action", ""),
                        resource=r.get("resource", ""),
                        severity=r.get("severity", ""),
                        timestamp=r.get("timestamp", ""),
                    )
                    for r in rows
                ]

    def get_all_events(self, since_rfc3339: str) -> list[DaemonEvent]:
        return asyncio.run(self._call_tool("get_all_events", since_rfc3339))

    def get_critical_events(self, since_rfc3339: str) -> list[DaemonEvent]:
        return asyncio.run(self._call_tool("get_critical_events", since_rfc3339))

    def find_matching_event(self, resource: str, events: list[DaemonEvent]) -> DaemonEvent | None:
        for e in events:
            if e.resource == resource:
                return e
        return None
