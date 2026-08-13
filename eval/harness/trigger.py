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
    t0 = time.time()
    _docker_exec(container, "sh", "-c", f"echo eval-write >> /app/keystore/id_eval_{repeat_index}")
    return TriggerResult(chain_name="keystore_write", t0=t0, mechanism="fsnotify")


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
    return TriggerResult(chain_name="env_write", t0=t0, mechanism="fsnotify")


def trigger_suspicious_outbound(container: str, listener_host: str, port: int) -> TriggerResult:
    """Network chain is poll-based (/proc/net/tcp) -- holds the connection
    open for the configured poll_interval so a scan between polls can't miss
    it entirely, and varies the destination PORT per repeat so each is a
    distinct resource surviving signal_dedup (Step 0.5 H1).

    NOT YET VERIFIED LIVE (known gap, next concrete task): live testing found
    network_linux.go classifies an unrecognized port as SeverityMedium
    ("non-standard port"), below min_severity=high -- config.eval.yaml's
    port 8090 target never fires. The actual suspiciousPorts set
    (4444/4445/1337/31337, real reverse-shell/C2 ports) IS SeverityCritical
    and would pass the filter, but nothing listens there today to keep the
    connection ESTABLISHED long enough for the poller to observe it (a bare
    RST'd connection attempt doesn't linger in /proc/net/tcp). Needs a decoy
    accept-only listener on one of those ports before this chain is real."""
    _assert_daemon_container(container)
    t0 = time.time()
    # sleep 2 keeps the socket open across a >=1s poll_interval; background
    # so this call returns promptly and t0 stays tight to the connect attempt
    connect_snippet = f"import socket,time; s=socket.socket(); s.connect(('{listener_host}', {port})); time.sleep(2)"
    _docker_exec(container, "sh", "-c", f'python3 -c "{connect_snippet}" &')
    return TriggerResult(chain_name="suspicious_outbound", t0=t0, mechanism="poll")


def run_all_chains(container: str, n_repeats: int, listener_host: str, base_port: int) -> list[TriggerResult]:
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
        results.append(trigger_suspicious_outbound(container, listener_host, base_port + i))
    return results
