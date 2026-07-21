import csv
from datetime import datetime, timedelta, timezone
import json
import sys
from types import SimpleNamespace

import pytest

import port_scanner as scanner
from portscanner import connect_scan, net, service_id, synscan


class FakeFuture:
    def __init__(self, value=None, *, done=True, exception=None):
        self.value = value
        self._done = done
        self.exception = exception
        self.was_cancelled = False

    def result(self):
        if self.exception is not None:
            raise self.exception
        return self.value

    def done(self):
        return self._done

    def cancelled(self):
        return self.was_cancelled

    def cancel(self):
        self.was_cancelled = True
        return True


class FakeExecutor:
    def __init__(self, futures):
        self.futures = list(futures)
        self.shutdown_calls = []

    def submit(self, *_args, **_kwargs):
        return self.futures.pop(0)

    def shutdown(self, wait=True, cancel_futures=False):
        self.shutdown_calls.append((wait, cancel_futures))


def interrupt_after_first(futures):
    futures = list(futures)
    if futures:
        yield futures[0]
    raise KeyboardInterrupt


def test_scan_interrupted_sorts_results_and_records_stage_progress():
    exc = scanner.ScanInterrupted(
        [
            scanner.make_result(80, "open", "ok"),
            scanner.make_result(22, "filtered", "timeout"),
        ],
        stage="TCP connect scan",
        stage_completed=2,
        stage_total=100,
    )

    assert [row["port"] for row in exc.results] == [22, 80]
    assert exc.stage == "TCP connect scan"
    assert exc.stage_completed == 2
    assert exc.stage_total == 100


def test_connect_scan_preserves_completed_results_on_interrupt(monkeypatch):
    first = FakeFuture(scanner.make_result(80, "open", "ok"))
    pending = FakeFuture(done=False)
    executor = FakeExecutor([first, pending])

    monkeypatch.setattr(connect_scan, "ThreadPoolExecutor", lambda **_kwargs: executor)
    monkeypatch.setattr(connect_scan, "as_completed", interrupt_after_first)

    with pytest.raises(scanner.ScanInterrupted) as exc_info:
        scanner.tcp_connect_scan(
            "192.0.2.1", [80, 81], max_threads=2, progress=False
        )

    exc = exc_info.value
    assert [row["port"] for row in exc.results] == [80]
    assert exc.stage == "TCP connect scan"
    assert exc.stage_completed == 1
    assert exc.stage_total == 2
    assert pending.was_cancelled is True
    assert executor.shutdown_calls == [(False, True)]


def test_service_identification_preserves_completed_banners_on_interrupt(monkeypatch):
    first = FakeFuture(("HTTP", "HTTP/1.1 200 OK"))
    pending = FakeFuture(done=False)
    executor = FakeExecutor([first, pending])
    results = [
        scanner.make_result(80, "open", "ok"),
        scanner.make_result(443, "open", "ok"),
    ]

    monkeypatch.setattr(service_id, "ThreadPoolExecutor", lambda **_kwargs: executor)
    monkeypatch.setattr(service_id, "as_completed", interrupt_after_first)

    with pytest.raises(scanner.ScanInterrupted) as exc_info:
        scanner.identify_open_services(
            "example.test",
            "192.0.2.1",
            results,
            timeout=0.1,
            max_workers=2,
            progress=False,
        )

    exc = exc_info.value
    assert exc.results[0]["service"] == "HTTP"
    assert exc.results[0]["banner"] == "HTTP/1.1 200 OK"
    assert exc.results[1]["banner"] == ""
    assert exc.stage == "service identification"
    assert exc.stage_completed == 1
    assert exc.stage_total == 2
    assert pending.was_cancelled is True


def test_syn_scan_preserves_classified_responses_on_interrupt(monkeypatch):
    tcp_layer = object()

    class FakeSent:
        def __init__(self, port):
            self.layer = SimpleNamespace(dport=port, sport=40000 + port)

        def __getitem__(self, layer):
            assert layer is tcp_layer
            return self.layer

    class FakeResponse:
        def haslayer(self, _layer):
            return False

    monkeypatch.setattr(synscan, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(synscan.os, "geteuid", lambda: 0)
    monkeypatch.setattr(synscan, "conf", SimpleNamespace(verb=1), raising=False)
    monkeypatch.setattr(synscan, "TCP", tcp_layer, raising=False)
    monkeypatch.setattr(
        synscan,
        "build_syn_packets",
        lambda _ip, ports: [FakeSent(port) for port in ports],
    )
    monkeypatch.setattr(
        synscan,
        "classify_syn_response",
        lambda _response: ("closed", "RST"),
    )
    monkeypatch.setattr(synscan, "send", lambda *_a, **_k: None, raising=False)

    calls = 0

    def fake_sr(packets, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return [(packets[0], FakeResponse())], packets[1:]
        raise KeyboardInterrupt

    monkeypatch.setattr(synscan, "sr", fake_sr, raising=False)

    with pytest.raises(scanner.ScanInterrupted) as exc_info:
        scanner.syn_scan(
            "192.0.2.1",
            list(range(1, 34)),
            batch_size=32,
            retries=0,
            progress=False,
        )

    exc = exc_info.value
    assert [row["port"] for row in exc.results] == [1]
    assert exc.results[0]["state"] == "closed"
    assert exc.stage == "SYN scan"
    assert exc.stage_completed == 1
    assert exc.stage_total == 33


def test_report_progress_handles_partial_and_empty_scans():
    results = [scanner.make_result(80, "open", "ok")]
    assert scanner.report_progress(results, 4) == (1, 4, 25.0)
    assert scanner.report_progress([], 0) == (0, 0, 100.0)


@pytest.fixture
def interrupted_report_data():
    started = datetime(2026, 7, 18, 10, 0, tzinfo=timezone(timedelta(hours=5)))
    finished = started + timedelta(seconds=2)
    results = [scanner.make_result(80, "open", "ok", service="HTTP")]
    return started, finished, results


def test_json_report_records_interruption_metadata(tmp_path, interrupted_report_data):
    started, finished, results = interrupted_report_data
    path = tmp_path / "partial.json"

    scanner.write_report(
        path,
        "router.local",
        "192.0.2.1",
        results,
        2.0,
        "TCP connect scan (socket)",
        started,
        finished,
        status="interrupted",
        interrupted_stage="TCP connect scan",
        ports_requested=100,
        stage_completed=1,
        stage_total=100,
    )

    document = json.loads(path.read_text(encoding="utf-8"))
    scan = document["scan"]
    assert scan["status"] == "interrupted"
    assert scan["interrupted"] is True
    assert scan["interrupted_stage"] == "TCP connect scan"
    assert scan["ports_requested"] == 100
    assert scan["ports_completed"] == 1
    assert scan["completion_percent"] == 1.0
    assert scan["stage_progress"] == {"completed": 1, "total": 100}


def test_text_report_labels_partial_progress(tmp_path, interrupted_report_data):
    started, finished, results = interrupted_report_data
    path = tmp_path / "partial.txt"

    scanner.write_report(
        path,
        "router.local",
        "192.0.2.1",
        results,
        2.0,
        "TCP connect scan (socket)",
        started,
        finished,
        status="interrupted",
        interrupted_stage="TCP connect scan",
        ports_requested=100,
        stage_completed=1,
        stage_total=100,
    )

    text = path.read_text(encoding="utf-8")
    assert "Status    : interrupted" in text
    assert "Interrupted: TCP connect scan" in text
    assert "Progress  : 1/100 port result(s) (1.00%)" in text
    assert "Ports     : 1 of 100 completed" in text


def test_csv_report_includes_partial_metadata(tmp_path, interrupted_report_data):
    started, finished, results = interrupted_report_data
    path = tmp_path / "partial.csv"

    scanner.write_report(
        path,
        "router.local",
        "192.0.2.1",
        results,
        2.0,
        "TCP connect scan (socket)",
        started,
        finished,
        status="interrupted",
        interrupted_stage="TCP connect scan",
        ports_requested=100,
        stage_completed=1,
        stage_total=100,
    )

    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0]["scan_status"] == "interrupted"
    assert rows[0]["interrupted_stage"] == "TCP connect scan"
    assert rows[0]["ports_requested"] == "100"
    assert rows[0]["ports_completed"] == "1"
    assert rows[0]["stage_completed"] == "1"


def install_main_basics(monkeypatch):
    monkeypatch.setattr(net, "resolve_target", lambda _target: "192.0.2.1")
    monkeypatch.setattr(scanner, "parse_ports", lambda _spec: [22, 23, 80])
    monkeypatch.setattr(scanner, "print_results", lambda *_a, **_k: None)
    monkeypatch.setattr(scanner.time, "perf_counter", lambda: 10.0)


def test_main_writes_partial_report_and_returns_130(monkeypatch, tmp_path, capsys):
    install_main_basics(monkeypatch)
    partial = [scanner.make_result(22, "filtered", "timeout")]

    def interrupt(*_args, **_kwargs):
        raise scanner.ScanInterrupted(
            partial,
            stage="TCP connect scan",
            stage_completed=1,
            stage_total=3,
        )

    captured = {}

    def write_report(path, *_args, **kwargs):
        captured["path"] = path
        captured.update(kwargs)
        return "json", 1

    monkeypatch.setattr(scanner, "tcp_connect_scan", interrupt)
    monkeypatch.setattr(scanner, "write_report", write_report)
    output = tmp_path / "partial.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["port_scanner.py", "example.test", "--no-banner", "-o", str(output)],
    )

    assert scanner.main() == 130
    assert captured["path"] == str(output)
    assert captured["status"] == "interrupted"
    assert captured["interrupted_stage"] == "TCP connect scan"
    assert captured["ports_requested"] == 3
    assert captured["stage_completed"] == 1
    assert captured["stage_total"] == 3
    assert "Partial report written" in capsys.readouterr().out


def test_main_explains_when_interrupted_without_output(monkeypatch, capsys):
    install_main_basics(monkeypatch)

    def interrupt(*_args, **_kwargs):
        raise scanner.ScanInterrupted([], "TCP connect scan", 0, 3)

    monkeypatch.setattr(scanner, "tcp_connect_scan", interrupt)
    monkeypatch.setattr(
        sys,
        "argv",
        ["port_scanner.py", "example.test", "--no-banner"],
    )

    assert scanner.main() == 130
    output = capsys.readouterr().out
    assert "Scan interrupted during TCP connect scan" in output
    assert "No partial report saved" in output


def test_completed_json_report_has_completion_metadata(tmp_path, interrupted_report_data):
    started, finished, results = interrupted_report_data
    path = tmp_path / "complete.json"
    scanner.write_report(
        path,
        "router.local",
        "192.0.2.1",
        results,
        2.0,
        "TCP connect scan (socket)",
        started,
        finished,
    )
    scan = json.loads(path.read_text(encoding="utf-8"))["scan"]
    assert scan["status"] == "completed"
    assert scan["interrupted"] is False
    assert scan["ports_requested"] == 1
    assert scan["ports_completed"] == 1
    assert scan["completion_percent"] == 100.0


class FailingExecutor(FakeExecutor):
    def __init__(self, first_future):
        super().__init__([first_future])
        self.submit_calls = 0

    def submit(self, *_args, **_kwargs):
        self.submit_calls += 1
        if self.submit_calls == 2:
            raise RuntimeError("submission failed")
        return super().submit(*_args, **_kwargs)


def test_connect_scan_cleans_up_executor_on_non_interrupt_failure(monkeypatch):
    pending = FakeFuture(done=False)
    executor = FailingExecutor(pending)
    monkeypatch.setattr(connect_scan, "ThreadPoolExecutor", lambda **_kwargs: executor)

    with pytest.raises(RuntimeError, match="submission failed"):
        scanner.tcp_connect_scan(
            "192.0.2.1", [80, 81], max_threads=2, progress=False
        )

    assert pending.was_cancelled is True
    assert executor.shutdown_calls == [(False, True)]


def test_service_identification_cleans_up_executor_on_failure(monkeypatch):
    pending = FakeFuture(done=False)
    executor = FailingExecutor(pending)
    monkeypatch.setattr(service_id, "ThreadPoolExecutor", lambda **_kwargs: executor)
    results = [
        scanner.make_result(80, "open", "ok"),
        scanner.make_result(443, "open", "ok"),
    ]

    with pytest.raises(RuntimeError, match="submission failed"):
        scanner.identify_open_services(
            "example.test",
            "192.0.2.1",
            results,
            timeout=0.1,
            max_workers=2,
            progress=False,
        )

    assert pending.was_cancelled is True
    assert executor.shutdown_calls == [(False, True)]
