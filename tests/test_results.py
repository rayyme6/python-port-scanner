from collections import Counter

import port_scanner as scanner


def sample_results():
    return [
        scanner.make_result(22, "filtered", "timeout"),
        scanner.make_result(23, "open", "connection succeeded", banner="Welcome"),
        scanner.make_result(80, "open", "connection succeeded", service="HTTP", banner="HTTP/1.1 200 OK"),
        scanner.make_result(81, "closed", "connection refused"),
        scanner.make_result(82, "error", "local failure"),
    ]


def test_make_result_uses_common_service_for_open_port():
    result = scanner.make_result(23, "open", "connection succeeded")
    assert result["service"] == "Telnet"


def test_make_result_does_not_guess_service_for_closed_port():
    result = scanner.make_result(80, "closed", "connection refused")
    assert result["service"] == "unknown"


def test_select_results_hides_non_open_rows_by_default():
    assert [row["port"] for row in scanner.select_results(sample_results(), False)] == [23, 80]


def test_select_results_can_show_every_state():
    assert len(scanner.select_results(sample_results(), True)) == 5


def test_report_filter_is_independent_from_terminal_filter():
    assert [row["port"] for row in scanner.select_report_results(sample_results(), True)] == [23, 80]
    assert len(scanner.select_report_results(sample_results(), False)) == 5


def test_summary_includes_error_only_when_present():
    counts = Counter({"open": 2, "closed": 1, "filtered": 1, "error": 1})
    assert scanner.summary_dict(counts) == {
        "open": 2,
        "closed": 1,
        "filtered": 1,
        "error": 1,
    }
    assert scanner.summary_text(counts) == "2 open, 1 closed, 1 filtered, 1 error"


def test_normalized_result_has_stable_schema():
    normalized = scanner.normalized_result({"port": 80, "state": "open"})
    assert normalized == {
        "port": 80,
        "state": "open",
        "service": "unknown",
        "banner": "",
        "reason": "",
    }
