import csv
from datetime import datetime, timedelta, timezone
import json
import socket
import sys

import pytest

import port_scanner as scanner


def test_read_target_file_ignores_comments_and_blank_lines(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text(
        "# devices\n\n192.0.2.1\nexample.test  # web server\n::1\n",
        encoding="utf-8",
    )
    assert scanner.read_target_file(path) == ["192.0.2.1", "example.test", "::1"]


def test_read_target_file_reports_io_error(tmp_path):
    with pytest.raises(ValueError, match="could not read target file"):
        scanner.read_target_file(tmp_path / "missing.txt")


def test_collect_targets_expands_ipv4_cidr_and_tracks_source():
    targets = scanner.collect_targets(["192.0.2.0/30"])
    assert [item["resolved_ip"] for item in targets] == ["192.0.2.1", "192.0.2.2"]
    assert all(item["expanded_from"] == "192.0.2.0/30" for item in targets)
    assert all(item["address_family"] == "IPv4" for item in targets)


def test_collect_targets_supports_ipv4_point_to_point_cidr():
    targets = scanner.collect_targets(["192.0.2.0/31"])
    assert [item["resolved_ip"] for item in targets] == ["192.0.2.0", "192.0.2.1"]


def test_collect_targets_expands_ipv6_cidr():
    targets = scanner.collect_targets(["2001:db8::/126"], family="ipv6")
    assert [item["resolved_ip"] for item in targets] == [
        "2001:db8::1",
        "2001:db8::2",
        "2001:db8::3",
    ]
    assert all(item["address_family"] == "IPv6" for item in targets)


def test_collect_targets_deduplicates_resolved_addresses(monkeypatch):
    addresses = {"one.test": "192.0.2.10", "two.test": "192.0.2.10"}
    monkeypatch.setattr(scanner, "resolve_target", lambda target: addresses[target])
    targets = scanner.collect_targets(["one.test", "two.test", "192.0.2.10/32"])
    assert len(targets) == 1
    assert targets[0]["input"] == "one.test"



def test_collect_targets_counts_overlapping_cidr_only_once(monkeypatch):
    monkeypatch.setattr(scanner, "resolve_target", lambda _target: "192.0.2.1")
    targets = scanner.collect_targets(
        ["router.test", "192.0.2.0/30"], max_targets=2
    )
    assert [item["resolved_ip"] for item in targets] == ["192.0.2.1", "192.0.2.2"]

def test_collect_targets_combines_cli_and_file(monkeypatch, tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("file.test\n", encoding="utf-8")
    addresses = {"cli.test": "192.0.2.1", "file.test": "192.0.2.2"}
    monkeypatch.setattr(scanner, "resolve_target", lambda target: addresses[target])
    targets = scanner.collect_targets(["cli.test"], [path])
    assert [item["resolved_ip"] for item in targets] == ["192.0.2.1", "192.0.2.2"]


def test_collect_targets_rejects_missing_input():
    with pytest.raises(ValueError, match="at least one TARGET"):
        scanner.collect_targets([])


def test_collect_targets_rejects_cidr_over_limit():
    with pytest.raises(ValueError, match="expands to 254 host"):
        scanner.collect_targets(["192.0.2.0/24"], max_targets=10)


def test_collect_targets_rejects_forced_family_mismatch():
    with pytest.raises(ValueError, match="--6 was requested"):
        scanner.collect_targets(["192.0.2.0/30"], family="ipv6")


def test_validate_probe_plan_accepts_and_rejects_limits():
    assert scanner.validate_probe_plan(4, 100, 500) == 400
    with pytest.raises(ValueError, match="exceeding --max-probes"):
        scanner.validate_probe_plan(4, 100, 399)


def test_parser_exposes_multi_target_options():
    args = scanner.build_parser().parse_args([
        "192.0.2.1", "192.0.2.2", "--targets-file", "targets.txt"
    ])
    assert args.target == ["192.0.2.1", "192.0.2.2"]
    assert args.targets_file == ["targets.txt"]
    assert args.max_targets == scanner.DEFAULT_MAX_TARGETS
    assert args.max_probes == scanner.DEFAULT_MAX_PROBES


def sample_runs():
    started = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
    return [
        {
            "target": "192.0.2.1",
            "ip": "192.0.2.1",
            "expanded_from": "192.0.2.0/30",
            "results": [scanner.make_result(80, "open", "ok", service="HTTP")],
            "elapsed": 0.1,
            "started_at": started,
            "finished_at": started + timedelta(seconds=0.1),
            "status": "completed",
            "interrupted_stage": None,
            "stage_completed": None,
            "stage_total": None,
        },
        {
            "target": "192.0.2.2",
            "ip": "192.0.2.2",
            "expanded_from": "192.0.2.0/30",
            "results": [scanner.make_result(80, "closed", "refused")],
            "elapsed": 0.2,
            "started_at": started,
            "finished_at": started + timedelta(seconds=0.2),
            "status": "completed",
            "interrupted_stage": None,
            "stage_completed": None,
            "stage_total": None,
        },
    ]


def test_batch_json_report_contains_targets_and_aggregate_summary(tmp_path):
    runs = sample_runs()
    started = runs[0]["started_at"]
    path = tmp_path / "batch.json"
    fmt, rows = scanner.write_batch_report(
        path, runs, "connect", started, started + timedelta(seconds=1), 1.0,
        ports_per_target=1, targets_requested=2, planned_probes=2,
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    assert fmt == "json"
    assert rows == 2
    assert document["batch"]["targets_completed"] == 2
    assert document["batch"]["planned_probes"] == 2
    assert document["summary"] == {"open": 1, "closed": 1, "filtered": 0, "error": 0}
    assert len(document["targets"]) == 2
    assert document["targets"][0]["target"]["expanded_from"] == "192.0.2.0/30"


def test_batch_csv_report_contains_one_row_per_result(tmp_path):
    runs = sample_runs()
    started = runs[0]["started_at"]
    path = tmp_path / "batch.csv"
    scanner.write_batch_report(
        path, runs, "connect", started, started + timedelta(seconds=1), 1.0,
        ports_per_target=1, targets_requested=2, planned_probes=2,
    )
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 2
    assert rows[0]["target_index"] == "1"
    assert rows[1]["resolved_ip"] == "192.0.2.2"


def install_batch_main(monkeypatch):
    monkeypatch.setattr(scanner, "parse_ports", lambda _spec: [80])
    monkeypatch.setattr(scanner, "identify_open_services", lambda *_a, **_k: None)
    monkeypatch.setattr(scanner, "print_results", lambda *_a, **_k: None)
    monkeypatch.setattr(scanner.time, "perf_counter", lambda: 10.0)
    monkeypatch.setattr(
        scanner,
        "collect_targets",
        lambda *_a, **_k: [
            {"input": "a", "resolved_ip": "192.0.2.1", "address_family": "IPv4", "expanded_from": None},
            {"input": "b", "resolved_ip": "192.0.2.2", "address_family": "IPv4", "expanded_from": None},
        ],
    )


def test_main_scans_multiple_targets_and_writes_batch_report(monkeypatch, tmp_path):
    install_batch_main(monkeypatch)
    scanned = []
    monkeypatch.setattr(
        scanner,
        "tcp_connect_scan",
        lambda ip, *_a, **_k: scanned.append(ip) or [scanner.make_result(80, "open", "ok")],
    )
    captured = {}
    monkeypatch.setattr(
        scanner,
        "write_batch_report",
        lambda path, runs, *_a, **_k: captured.update(path=path, runs=runs) or ("json", 2),
    )
    output = tmp_path / "batch.json"
    monkeypatch.setattr(sys, "argv", [
        "portscan", "a", "b", "--no-banner", "-o", str(output)
    ])
    assert scanner.main() == 0
    assert scanned == ["192.0.2.1", "192.0.2.2"]
    assert captured["path"] == str(output)
    assert len(captured["runs"]) == 2


def test_main_stops_after_interrupted_target(monkeypatch):
    install_batch_main(monkeypatch)
    calls = []

    def scan(ip, *_args, **_kwargs):
        calls.append(ip)
        raise scanner.ScanInterrupted([], "TCP connect scan", 0, 1)

    monkeypatch.setattr(scanner, "tcp_connect_scan", scan)
    monkeypatch.setattr(sys, "argv", ["portscan", "a", "b", "--no-banner"])
    assert scanner.main() == 130
    assert calls == ["192.0.2.1"]
