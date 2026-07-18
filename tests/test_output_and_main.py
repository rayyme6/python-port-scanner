from datetime import datetime, timezone
import sys

import pytest

import port_scanner as scanner


def test_print_results_open_only(capsys):
    results = [
        scanner.make_result(22, "filtered", "timeout"),
        scanner.make_result(80, "open", "ok", service="HTTP", banner="X" * 130),
    ]
    scanner.print_results("host", "192.0.2.1", results, 1.234, "connect")
    output = capsys.readouterr().out
    assert "1 open, 0 closed, 1 filtered" in output
    assert "80" in output
    assert "22      filtered" not in output
    assert "…" in output


def test_print_results_handles_no_open_ports(capsys):
    scanner.print_results(
        "host",
        "192.0.2.1",
        [scanner.make_result(80, "closed", "refused")],
        0.1,
        "connect",
    )
    assert "No open ports found" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("function", "valid", "invalid_text", "invalid_range"),
    [
        (scanner.positive_int, "2", "x", "0"),
        (scanner.non_negative_int, "0", "x", "-1"),
        (scanner.positive_float, "0.5", "x", "0"),
        (scanner.non_negative_float, "0", "x", "-0.1"),
    ],
)
def test_numeric_argument_validators(function, valid, invalid_text, invalid_range):
    assert function(valid) >= 0
    with pytest.raises(scanner.argparse.ArgumentTypeError):
        function(invalid_text)
    with pytest.raises(scanner.argparse.ArgumentTypeError):
        function(invalid_range)


def install_main_basics(monkeypatch):
    monkeypatch.setattr(scanner, "resolve_target", lambda _target: "192.0.2.1")
    monkeypatch.setattr(scanner, "parse_ports", lambda _spec: [80])
    monkeypatch.setattr(scanner, "identify_open_services", lambda *_a, **_k: None)
    monkeypatch.setattr(scanner, "print_results", lambda *_a, **_k: None)
    monkeypatch.setattr(scanner.time, "perf_counter", lambda: 10.0)



def test_main_connect_path(monkeypatch):
    install_main_basics(monkeypatch)
    expected = [scanner.make_result(80, "open", "ok")]
    monkeypatch.setattr(scanner, "tcp_connect_scan", lambda *_a, **_k: expected)
    monkeypatch.setattr(sys, "argv", ["port_scanner.py", "example.test", "--no-banner"])
    assert scanner.main() == 0


def test_main_syn_path(monkeypatch):
    install_main_basics(monkeypatch)
    monkeypatch.setattr(
        scanner,
        "syn_scan",
        lambda *_a, **_k: [scanner.make_result(80, "closed", "RST")],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["port_scanner.py", "example.test", "--syn", "--no-banner"],
    )
    assert scanner.main() == 0


def test_main_writes_requested_report(monkeypatch, tmp_path, capsys):
    install_main_basics(monkeypatch)
    monkeypatch.setattr(
        scanner,
        "tcp_connect_scan",
        lambda *_a, **_k: [scanner.make_result(80, "open", "ok")],
    )
    captured = {}

    def write_report(path, *args, **kwargs):
        captured["path"] = path
        captured["format"] = kwargs["output_format"]
        captured["open_only"] = kwargs["open_only"]
        return "json", 1

    monkeypatch.setattr(scanner, "write_report", write_report)
    output = tmp_path / "scan.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "port_scanner.py",
            "example.test",
            "--no-banner",
            "-o",
            str(output),
            "--report-open-only",
        ],
    )

    assert scanner.main() == 0
    assert captured == {"path": str(output), "format": "auto", "open_only": True}
    assert "Report written" in capsys.readouterr().out


def test_main_returns_one_on_scan_error(monkeypatch):
    install_main_basics(monkeypatch)

    def fail(*_args, **_kwargs):
        raise OSError("scan failed")

    monkeypatch.setattr(scanner, "tcp_connect_scan", fail)
    monkeypatch.setattr(sys, "argv", ["port_scanner.py", "example.test", "--no-banner"])
    assert scanner.main() == 1


def test_main_requires_output_for_output_options(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["port_scanner.py", "example.test", "--output-format", "json"],
    )
    with pytest.raises(SystemExit) as exc_info:
        scanner.main()
    assert exc_info.value.code == 2
