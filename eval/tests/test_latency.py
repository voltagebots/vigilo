from harness.latency import aggregate_latencies, compute_latency
from harness.trigger import TriggerResult
from harness.webhook_listener import AlertReceived


def test_compute_latency_ms():
    trigger = TriggerResult(chain_name="keystore_write", t0=100.0, mechanism="fsnotify", resource="/app/keystore/x")
    alert = AlertReceived(t1=100.05, payload={})
    metric = compute_latency(trigger, alert)
    assert metric is not None
    assert abs(metric.latency_ms - 50.0) < 0.01


def test_compute_latency_rejects_negative():
    """Clock skew or mispairing -- t1 before t0 -- must not report a
    nonsense negative number."""
    trigger = TriggerResult(chain_name="keystore_write", t0=100.0, mechanism="fsnotify", resource="/app/keystore/x")
    alert = AlertReceived(t1=99.0, payload={})
    assert compute_latency(trigger, alert) is None


def test_aggregate_latencies_empty_reports_no_data():
    report = aggregate_latencies([])
    assert report.state == "no data"
    assert report.per_chain == {}


def test_aggregate_latencies_mechanism_labeling():
    """Regression: poll_interval must only attach to poll-based chains, not
    blended into fsnotify (event-driven) chain numbers (Step 0.5 H2)."""
    metrics = [
        compute_latency(
            TriggerResult(chain_name="keystore_write", t0=0.0, mechanism="fsnotify", resource="/app/keystore/x"),
            AlertReceived(t1=0.01, payload={}),
        ),
        compute_latency(
            TriggerResult(chain_name="suspicious_outbound", t0=0.0, mechanism="poll", resource=":4444"),
            AlertReceived(t1=1.0, payload={}),
        ),
    ]
    report = aggregate_latencies(metrics, poll_interval_ms=1000.0)
    assert "poll_interval_ms" not in report.per_chain["keystore_write"]
    assert report.per_chain["suspicious_outbound"]["poll_interval_ms"] == 1000.0


def test_aggregate_latencies_per_chain_median_and_p95():
    metrics = [
        compute_latency(
            TriggerResult(chain_name="keystore_write", t0=0.0, mechanism="fsnotify", resource="/app/keystore/x"),
            AlertReceived(t1=t / 1000, payload={}),
        )
        for t in (10, 20, 30, 40, 100)
    ]
    report = aggregate_latencies(metrics)
    chain = report.per_chain["keystore_write"]
    assert chain["n"] == 5
    assert chain["median_ms"] == 30.0
