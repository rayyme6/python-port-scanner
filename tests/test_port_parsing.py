import socket

import pytest

import port_scanner as scanner


@pytest.mark.parametrize(
    ("specification", "expected"),
    [
        ("22", [22]),
        ("22,80,443", [22, 80, 443]),
        ("100-102", [100, 101, 102]),
        ("80,80,79-81", [79, 80, 81]),
        (" 22 , 80-82 ", [22, 80, 81, 82]),
        ("1,65535", [1, 65535]),
    ],
)
def test_parse_ports_accepts_valid_specs(specification, expected):
    assert scanner.parse_ports(specification) == expected


@pytest.mark.parametrize(
    "specification",
    ["", ",,,", "0", "65536", "100-50", "abc", "1-2-3", "-1", "22-"],
)
def test_parse_ports_rejects_invalid_specs(specification):
    with pytest.raises(ValueError):
        scanner.parse_ports(specification)


def test_chunked_splits_values_without_dropping_items():
    assert list(scanner.chunked([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]


def test_resolve_target_uses_ipv4_resolver(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda target: "203.0.113.7")
    assert scanner.resolve_target("example.test") == "203.0.113.7"


def test_resolve_target_turns_dns_failure_into_value_error(monkeypatch):
    def fail(_target):
        raise socket.gaierror("not found")

    monkeypatch.setattr(socket, "gethostbyname", fail)
    with pytest.raises(ValueError, match="could not resolve host"):
        scanner.resolve_target("missing.test")
