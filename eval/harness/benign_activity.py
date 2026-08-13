"""Generates real benign activity inside the daemon's own container for
the V3 false-positive window -- ordinary file/process operations that
should NOT fire an alert, distinct from trigger.py's deliberate attack
chains. Confirmed execution (not daemon-side detection, see
false_positive.py's docstring) is what makes the window non-vacuous."""

from __future__ import annotations

from harness.trigger import DAEMON_CONTAINER, _assert_daemon_container, _docker_exec


def run_benign_activity(container: str, repeat_index: int) -> None:
    """Ordinary operations a real dev container generates: reading/writing
    outside watch_paths, spawning harmless processes. None of these should
    classify as high/critical under severityForPath or the process/network
    heuristics."""
    _assert_daemon_container(container)
    _docker_exec(container, "sh", "-c", f"echo benign-{repeat_index} > /var/lib/vigilo/scratch_{repeat_index}.txt")
    _docker_exec(container, "sh", "-c", "ls /usr/local/bin > /dev/null")
    _docker_exec(container, "sh", "-c", "date > /dev/null")


if __name__ == "__main__":
    run_benign_activity(DAEMON_CONTAINER, 0)
