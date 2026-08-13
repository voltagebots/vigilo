from harness.false_positive import FalsePositiveWindow, compute_fp_rate


def test_vacuous_denominator_raises_state():
    """Step 0.5 C2 regression: if the benign window never produced
    observable activity, that's a measurement that never ran, not a
    Vigilo=precise result."""
    window = FalsePositiveWindow(duration_s=60.0, benign_events_observed=False, alert_count=0)
    report = compute_fp_rate(window)
    assert report.state == "vacuous"
    assert report.fp_rate_per_day is None


def test_reported_rate_is_extrapolated_per_day():
    window = FalsePositiveWindow(duration_s=3600.0, benign_events_observed=True, alert_count=2)
    report = compute_fp_rate(window)
    assert report.state == "reported"
    assert report.fp_count == 2
    assert abs(report.fp_rate_per_day - 48.0) < 0.01  # 2 per hour -> 48 per day


def test_workload_qualifier_always_attached():
    window = FalsePositiveWindow(duration_s=60.0, benign_events_observed=True, alert_count=0)
    report = compute_fp_rate(window)
    assert "not a production signer workload" in report.workload_qualifier
