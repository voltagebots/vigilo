from harness.host_overhead import OverheadReport, ResourceSample, _parse_mem_to_mib, compute_overhead_report


def test_parse_mem_to_mib_units():
    assert abs(_parse_mem_to_mib("15.19MiB") - 15.19) < 0.01
    assert abs(_parse_mem_to_mib("1.5GiB") - 1536.0) < 0.01
    assert abs(_parse_mem_to_mib("512KiB") - 0.5) < 0.01


def test_compute_overhead_report_bytes_per_event():
    idle = [ResourceSample(cpu_pct=0.1, mem_mib=15.0)]
    load = [ResourceSample(cpu_pct=2.0, mem_mib=18.0)]
    report = compute_overhead_report(idle, load, db_bytes_before=4096, db_bytes_after=8192, n_events=10)
    assert isinstance(report, OverheadReport)
    assert report.bytes_per_event == 409.6
    assert report.idle_cpu_pct_median == 0.1
    assert report.load_mem_mib_median == 18.0


def test_compute_overhead_report_no_growth_reports_none():
    """If the db size didn't measurably grow, report None rather than a
    misleading 0 bytes/event."""
    idle = [ResourceSample(cpu_pct=0.1, mem_mib=15.0)]
    load = [ResourceSample(cpu_pct=0.1, mem_mib=15.0)]
    report = compute_overhead_report(idle, load, db_bytes_before=4096, db_bytes_after=4096, n_events=10)
    assert report.bytes_per_event is None
