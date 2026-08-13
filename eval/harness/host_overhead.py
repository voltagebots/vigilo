"""V4 -- host overhead. Real docker stats sampling (idle vs under real
trigger load), plus SQLite write amplification (events.db byte growth per
real event). Event throughput ceiling (stress to the buffer's breaking
point) is NOT covered this pass -- disclosed as a gap, not silently
omitted, same as V1/V3's own disclosed scope limits."""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass

DAEMON_CONTAINER = "docker-daemon-1"


@dataclass(frozen=True)
class ResourceSample:
    cpu_pct: float
    mem_mib: float


@dataclass(frozen=True)
class OverheadReport:
    idle_cpu_pct_median: float
    idle_mem_mib_median: float
    load_cpu_pct_median: float
    load_mem_mib_median: float
    bytes_per_event: float | None  # None if db size didn't grow measurably


def _parse_mem_to_mib(mem_str: str) -> float:
    """docker stats reports like '15.19MiB' or '1.2GiB' -- normalize to MiB."""
    match = re.match(r"([\d.]+)(MiB|GiB|KiB)", mem_str)
    if not match:
        return 0.0
    value, unit = float(match.group(1)), match.group(2)
    return {"KiB": value / 1024, "MiB": value, "GiB": value * 1024}[unit]


def sample_resources(container: str) -> ResourceSample:
    out = subprocess.run(
        ["docker", "stats", container, "--no-stream", "--format", "{{.CPUPerc}} {{.MemUsage}}"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    cpu_str, mem_str = out.stdout.strip().split(" ", 1)
    mem_str = mem_str.split(" / ")[0]  # "15.19MiB / 15.66GiB" -> usage only
    return ResourceSample(cpu_pct=float(cpu_str.rstrip("%")), mem_mib=_parse_mem_to_mib(mem_str))


def sample_over_window(container: str, duration_s: float, interval_s: float = 1.0) -> list[ResourceSample]:
    samples = []
    start = time.time()
    while time.time() - start < duration_s:
        samples.append(sample_resources(container))
        time.sleep(interval_s)
    return samples


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def get_db_size_bytes(container: str, db_path: str = "/var/lib/vigilo/events.db") -> int:
    """CORRECTED (live measurement): SQLite in WAL mode (confirmed live --
    events.db-wal and events.db-shm both present) keeps the main .db file
    at a near-fixed size and writes real data into the WAL file until a
    checkpoint. Measuring only the main file reported zero growth across
    15 real events. Sums all three files for the real on-disk footprint."""
    total = 0
    for suffix in ("", "-wal", "-shm"):
        result = subprocess.run(
            ["docker", "exec", container, "stat", "-c", "%s", db_path + suffix],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            total += int(result.stdout.strip())
    return total


def compute_overhead_report(
    idle_samples: list[ResourceSample],
    load_samples: list[ResourceSample],
    db_bytes_before: int,
    db_bytes_after: int,
    n_events: int,
) -> OverheadReport:
    delta_bytes = db_bytes_after - db_bytes_before
    bytes_per_event = (delta_bytes / n_events) if n_events > 0 and delta_bytes > 0 else None
    return OverheadReport(
        idle_cpu_pct_median=_median([s.cpu_pct for s in idle_samples]),
        idle_mem_mib_median=_median([s.mem_mib for s in idle_samples]),
        load_cpu_pct_median=_median([s.cpu_pct for s in load_samples]),
        load_mem_mib_median=_median([s.mem_mib for s in load_samples]),
        bytes_per_event=bytes_per_event,
    )
