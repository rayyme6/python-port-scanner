import csv
from datetime import datetime, timedelta, timezone
import json

import pytest

import port_scanner as scanner


@pytest.fixture
def results():
    return [
        scanner.make_result(22, "filtered", "timeout"),
        scanner.make_result(
            80,
            "open",
            "connection succeeded",
            service="HTTP",
            banner="HTTP/1.1 200 OK",
        ),
        scanner.make_result(81, "closed", "connection refused"),
    ]


@pytest.fixture
def timestamps():
    started = datetime(2026, 7, 17, 15, 0, tzinfo=timezone(timedelta(hours=5)))
    finished = started + timedelta(seconds=1.25)
    return started, finished


@pytest.mark.parametrize(
    ("filename", "requested", "expected"),
    [
        ("report.txt", "auto", "text"),
        ("report.json", "auto", "json"),
        ("report.csv", "auto", "csv"),
        ("report.data", "json", "json"),
        ("REPORT.JSON", "auto", "json"),
    ],
)
def test_resolve_output_format(filename, requested, expected):
    assert scanner.resolve_output_format(filename, requested) == expected


def test_resolve_output_format_rejects_unknown_explicit_format():
    with pytest.raises(ValueError, match="unsupported output format"):
        scanner.resolve_output_format("report.out", "xml")


def test_json_report_contains_metadata_summary_and_all_results(tmp_path, results, timestamps):
    started, finished = timestamps
    path = tmp_path / "scan.json"
    output_format, rows = scanner.write_report(
        path,
        "router.local",
        "192.0.2.1",
        results,
        1.25,
        "TCP connect scan (socket)",
        started,
        finished,
    )

    document = json.loads(path.read_text(encoding="utf-8"))
    assert output_format == "json"
    assert rows == 3
    assert document["scanner"] == {"name": scanner.SCANNER_NAME, "version": scanner.SCANNER_VERSION}
    assert document["scan"]["report_scope"] == "all-states"
    assert document["scan"]["profile"] == "balanced"
    assert document["scan"]["profile_overrides"] == []
    assert document["scan"]["effective_settings"] == scanner.SCAN_PROFILES["balanced"]
    assert document["summary"] == {"open": 1, "closed": 1, "filtered": 1, "error": 0}
    assert [row["port"] for row in document["results"]] == [22, 80, 81]


def test_json_open_only_report_keeps_full_summary(tmp_path, results, timestamps):
    started, finished = timestamps
    path = tmp_path / "open.json"
    _, rows = scanner.write_report(
        path,
        "router.local",
        "192.0.2.1",
        results,
        1.25,
        "TCP connect scan (socket)",
        started,
        finished,
        open_only=True,
    )

    document = json.loads(path.read_text(encoding="utf-8"))
    assert rows == 1
    assert document["scan"]["report_scope"] == "open-only"
    assert document["summary"]["filtered"] == 1
    assert [row["port"] for row in document["results"]] == [80]


def test_csv_report_has_stable_columns_and_rows(tmp_path, results, timestamps):
    started, finished = timestamps
    path = tmp_path / "scan.csv"
    scanner.write_report(
        path,
        "router.local",
        "192.0.2.1",
        results,
        1.25,
        "TCP connect scan (socket)",
        started,
        finished,
    )

    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    assert len(rows) == 3
    assert rows[1]["port"] == "80"
    assert rows[1]["service"] == "HTTP"
    assert rows[1]["banner"] == "HTTP/1.1 200 OK"
    assert rows[1]["scanner_version"] == scanner.SCANNER_VERSION
    assert rows[1]["profile"] == "balanced"
    assert rows[1]["timeout"] == "1.0"
    assert rows[1]["threads"] == "100"


def test_text_report_contains_scope_summary_and_reason(tmp_path, results, timestamps):
    started, finished = timestamps
    path = tmp_path / "scan.txt"
    scanner.write_report(
        path,
        "router.local",
        "192.0.2.1",
        results,
        1.25,
        "TCP connect scan (socket)",
        started,
        finished,
    )

    text = path.read_text(encoding="utf-8")
    assert f"Scanner   : {scanner.SCANNER_NAME} {scanner.SCANNER_VERSION}" in text
    assert "Profile   : balanced" in text
    assert "Overrides : none" in text
    assert "Settings  : timeout=1s, threads=100, batch-size=512, inter=0.001s, retries=1" in text
    assert "Scope     : all states" in text
    assert "Summary   : 1 open, 1 closed, 1 filtered" in text
    assert "HTTP/1.1 200 OK" in text
    assert "timeout" in text


def test_reports_record_profile_overrides_and_effective_settings(tmp_path, results, timestamps):
    started, finished = timestamps
    path = tmp_path / "reliable.json"
    effective = {
        "timeout": 2.0,
        "threads": 50,
        "batch_size": 256,
        "inter": 0.003,
        "retries": 2,
    }

    scanner.write_report(
        path,
        "router.local",
        "192.0.2.1",
        results,
        1.25,
        "TCP connect scan (socket)",
        started,
        finished,
        profile="reliable",
        effective_settings=effective,
        profile_overrides=["timeout"],
    )

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["scan"]["profile"] == "reliable"
    assert document["scan"]["profile_overrides"] == ["timeout"]
    assert document["scan"]["effective_settings"] == effective
