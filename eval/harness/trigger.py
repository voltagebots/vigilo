"""Immediate-tier attack-chain triggers. Executes real actions inside the
DAEMON's own container -- never a sibling container (Step 0.5 C1): the
daemon's collectors read its own /proc, /proc/net/tcp, and fsnotify on its
own mount namespace, so an action exec'd elsewhere is invisible to it.

CORRECTED (live verification, 2026-08-13): the README's detection table
lists "keystore file read" as an immediate-tier signal, but
internal/collector/file.go only watches fsnotify.Write and fsnotify.Create
-- reads are not observable without the optional auditd integration, not
configured for this eval. Verified live: a `cat` on the watched path
produced no alert; a write to the same path fired correctly. Both file
chains here are WRITE-based, matching what this collector configuration
actually observes -- not what the README's threat-model table implies is
covered without further setup.

LLM-only signals (shell-spawn/RCE, exfil chain, priv-esc) are explicitly
out of scope -- the analyst tier is blocked on the same Anthropic billing
issue as memkit-eval's resolver work (Step 0 Q3)."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

DAEMON_CONTAINER = "docker-daemon-1"


@dataclass(frozen=True)
class TriggerResult:
    chain_name: str
    t0: float
    mechanism: str  # "fsnotify" | "poll"
    resource: str  # exact expected alert resource -- see run_evaluation.py's pairing note


def _assert_daemon_container(container: str) -> None:
    """Guards against C1 by construction -- triggers must never target a
    sibling container. Checked at call time, not just documented."""
    if container != DAEMON_CONTAINER:
        raise ValueError(f"trigger target must be the daemon's own container ({DAEMON_CONTAINER!r}), got {container!r}")


def _docker_exec(container: str, *cmd: str) -> None:
    result = subprocess.run(["docker", "exec", container, *cmd], capture_output=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"docker exec failed: {cmd!r}: {result.stderr.decode(errors='replace')}")


def trigger_keystore_write(container: str, repeat_index: int) -> TriggerResult:
    """CORRECTED (live verification): signal_cooldown suppresses repeat
    alerts on the SAME resource for its whole window regardless of content
    -- varying only the file's content (not its path) still collapsed to
    one alert. Each repeat writes to a genuinely distinct file path within
    the watched directory instead."""
    _assert_daemon_container(container)
    resource = f"/app/keystore/id_eval_{repeat_index}"
    t0 = time.time()
    _docker_exec(container, "sh", "-c", f"echo eval-write >> {resource}")
    return TriggerResult(chain_name="keystore_write", t0=t0, mechanism="fsnotify", resource=resource)


def trigger_env_write(container: str, repeat_index: int) -> TriggerResult:
    """/app/.env is watched as a specific file, not a directory -- unlike
    keystore_write, there is no sibling-path trick available here; a
    written-to sibling file simply isn't watched. Repeat isolation for this
    chain relies entirely on config.eval.yaml's signal_cooldown=0 (verified
    live: with cooldown=0, repeat writes to the same watched file each
    produced a new alert; with the original 1h default they did not)."""
    _assert_daemon_container(container)
    t0 = time.time()
    _docker_exec(container, "sh", "-c", f"echo EVAL={repeat_index} >> /app/.env")
    # resource is identical every repeat (a single watched file, no per-repeat
    # path trick available) -- pairing relies on chronological consume-once
    # matching in run_evaluation.py, not resource uniqueness, for this chain.
    return TriggerResult(chain_name="env_write", t0=t0, mechanism="fsnotify", resource="/app/.env")


# Real entries from internal/collector/network_linux.go's suspiciousPorts --
# these score SeverityCritical, unlike an arbitrary port (verified live:
# port 8090 classified as SeverityMedium, "non-standard port", below
# min_severity=high and never fired). DecoyListener (webhook_listener.py)
# accepts on all four inside the eval network so the connection stays
# ESTABLISHED long enough for the poller to observe it.
_SUSPICIOUS_PORTS = (4444, 4445, 1337, 31337)


def trigger_suspicious_outbound(container: str, listener_host: str, repeat_index: int) -> TriggerResult:
    """Network chain is poll-based (/proc/net/tcp) -- holds the connection
    open for the configured poll_interval so a scan between polls can't miss
    it entirely. Cycles through the real suspiciousPorts entries per repeat
    (both for genuine severity=critical classification, and so each repeat
    is a distinct resource surviving signal_dedup, Step 0.5 H1).

    CORRECTED (live verification): the daemon's own image is Alpine-based
    with no python3 -- every attempt using a python3 -c connect snippet
    silently failed. Compounded by a second real bug: the original call
    backgrounded the command with `&`, so _docker_exec's exit-code check
    could never have caught that failure anyway -- `sh -c "... &"` reports
    success the instant the background job launches, regardless of what it
    does. Fixed by running the connection attempt in the FOREGROUND with a
    bounded duration (matches _docker_exec's existing timeout), so a real
    failure actually surfaces as a real exception. Uses busybox nc
    (confirmed present, python3 isn't). A bare `nc host port` closes almost
    immediately (observed live: /proc/net/tcp state 06 TIME_WAIT within
    ~0.5s) -- piping a sleep as nc's stdin holds the connection open in
    state 01 ESTABLISHED for the sleep's duration without sending or
    expecting any data."""
    _assert_daemon_container(container)
    port = _SUSPICIOUS_PORTS[repeat_index % len(_SUSPICIOUS_PORTS)]
    t0 = time.time()
    _docker_exec(container, "sh", "-c", f"sleep 3 | nc {listener_host} {port}")
    # resource is "{listener_ip}:{port}" -- the compose-assigned IP isn't
    # known here, so callers match by port SUFFIX (still a real per-repeat
    # differentiator via the 4-port cycle), not full equality.
    return TriggerResult(chain_name="suspicious_outbound", t0=t0, mechanism="poll", resource=f":{port}")


def run_all_chains(container: str, n_repeats: int, listener_host: str) -> list[TriggerResult]:
    """Real gap found live: signal_dedup's cooldown check compares whole-second
    RFC3339 strings (buffer/sqlite.go IsDuplicate) -- with signal_cooldown=0,
    two events on the SAME resource landing in the same wall-clock second
    still collide (lastSeen >= cutoff is true when both round to now).
    keystore_write sidesteps this with a distinct path per repeat; env_write
    can't (a single watched file), so its repeats are spaced >1s apart. This
    doesn't distort the latency measurement itself -- t0/t1 are still per-
    trigger and independent -- it only paces how fast repeats fire."""
    _assert_daemon_container(container)
    results: list[TriggerResult] = []
    for i in range(n_repeats):
        results.append(trigger_keystore_write(container, i))
        results.append(trigger_env_write(container, i))
        time.sleep(1.1)
        results.append(trigger_suspicious_outbound(container, listener_host, i))
    return results
