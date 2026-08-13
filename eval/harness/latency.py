"""V1 -- detection latency scoring. t1 is always the webhook listener's own
receive wall-clock time (webhook_listener.py), never the payload's own
`timestamp` field (whole-second RFC3339, Step 0.5 H3) and never averaged
with the MCP path's detection-time timestamps (a different clock event
entirely -- cross-check only, harness/mcp_client.py)."""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from harness.trigger import TriggerResult
from harness.webhook_listener import AlertReceived


@dataclass(frozen=True)
class LatencyMetric:
    chain_name: str
    t0: float
    t1: float
    latency_ms: float
    mechanism: str  # "fsnotify" | "poll"


@dataclass(frozen=True)
class LatencyReport:
    state: str  # "reported" | "no data"
    per_chain: dict[str, dict]  # chain_name -> {median_ms, p95_ms, n, mechanism, poll_interval_ms}


def compute_latency(trigger: TriggerResult, alert: AlertReceived) -> LatencyMetric | None:
    """Rejects a negative latency (clock skew or mispairing) rather than
    reporting a nonsense number (Step 0.5 H2/C.5 correction)."""
    latency_ms = (alert.t1 - trigger.t0) * 1000
    if latency_ms < 0:
        return None
    return LatencyMetric(
        chain_name=trigger.chain_name, t0=trigger.t0, t1=alert.t1, latency_ms=latency_ms, mechanism=trigger.mechanism
    )


def aggregate_latencies(metrics: list[LatencyMetric], poll_interval_ms: float | None = None) -> LatencyReport:
    """Per-chain median/p95, mechanism label per chain -- poll_interval is
    only meaningful for poll-based chains, never blended into fsnotify
    (event-driven) chains' numbers as if it applied there too (Step 0.5 H2).
    Empty input reports state='no data' explicitly, never a silent 0ms."""
    if not metrics:
        return LatencyReport(state="no data", per_chain={})

    by_chain: dict[str, list[LatencyMetric]] = {}
    for m in metrics:
        by_chain.setdefault(m.chain_name, []).append(m)

    per_chain = {}
    for chain_name, chain_metrics in by_chain.items():
        values = sorted(m.latency_ms for m in chain_metrics)
        mechanism = chain_metrics[0].mechanism
        entry = {
            "median_ms": statistics.median(values),
            "p95_ms": values[int(len(values) * 0.95)] if len(values) > 1 else values[0],
            "n": len(values),
            "mechanism": mechanism,
        }
        if mechanism == "poll":
            entry["poll_interval_ms"] = poll_interval_ms
        per_chain[chain_name] = entry

    return LatencyReport(state="reported", per_chain=per_chain)
