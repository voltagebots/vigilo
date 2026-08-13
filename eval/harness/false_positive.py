"""V3 -- false-positive rate scoring. Splits positive control (liveness
check) from the FP denominator (Step 0.5 C2 BLOCKER) -- touching a watched
path is the designed true-positive signal, not a false positive; conflating
the two either inflates the published rate or contributes nothing.

FP rate is workload-specific by construction -- a bounded window of
in-container dev activity, not a real signer's noise profile. The
workload_qualifier travels with every FPReport, headline-level, not a
footnote (Step 0.5 HIGH)."""

from __future__ import annotations

from dataclasses import dataclass

WORKLOAD_QUALIFIER = "measured against a bounded window of in-container dev activity, not a production signer workload"


@dataclass(frozen=True)
class FalsePositiveWindow:
    duration_s: float
    benign_events_observed: bool  # collectors saw ANY benign-set activity -- non-vacuous check
    alert_count: int


@dataclass(frozen=True)
class FPReport:
    state: str  # "reported" | "vacuous"
    fp_count: int
    fp_rate_per_day: float | None
    workload_qualifier: str


def compute_fp_rate(window: FalsePositiveWindow) -> FPReport:
    """Refuses a vacuous FP=0: if the benign window never actually produced
    observable activity, a 0 count means the measurement never ran, not
    that Vigilo is precise (Step 0.5 C2)."""
    if not window.benign_events_observed:
        return FPReport(state="vacuous", fp_count=0, fp_rate_per_day=None, workload_qualifier=WORKLOAD_QUALIFIER)

    fp_rate_per_day = window.alert_count / (window.duration_s / 86400)
    return FPReport(
        state="reported",
        fp_count=window.alert_count,
        fp_rate_per_day=fp_rate_per_day,
        workload_qualifier=WORKLOAD_QUALIFIER,
    )
