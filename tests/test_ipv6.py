import json
import socket
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import port_scanner as scanner
from portscanner import connect_scan, net, synscan


def test_address_family_helpers_support_ipv4_and_ipv6():
    assert scanner.address_family("192.0.2.1") == socket.AF_INET
    assert scanner.address_family("2001:db8::1") == socket.AF_INET6
    assert scanner.address_family("[2001:db8::1]") == socket.AF_INET6
    assert scanner.address_family_name("192.0.2.1") == "IPv4"
    assert scanner.address_family_name("2001:db8::1") == "IPv6"


def test_socket_endpoint_builds_ipv6_four_tuple():
    assert scanner.socket_endpoint("2001:db8::1", 443) == (
        "2001:db8::1",
        443,
        0,
        0,
    )


def test_socket_endpoint_resolves_named_ipv6_scope(monkeypatch):
    monkeypatch.setattr(socket, "if_nametoindex", lambda name: 7 if name == "eth0" else 0)
    assert scanner.socket_endpoint("fe80::1%eth0", 80) == (
        "fe80::1",
        80,
        0,
        7,
    )


def test_resolve_target_accepts_ipv6_literals_and_brackets():
    assert scanner.resolve_target("2001:db8::5") == "2001:db8::5"
    assert scanner.resolve_target("[2001:db8::5]") == "2001:db8::5"


def test_resolve_target_rejects_forced_family_mismatch():
    with pytest.raises(ValueError, match="--4"):
        scanner.resolve_target("2001:db8::5", family="ipv4")
    with pytest.raises(ValueError, match="--6"):
        scanner.resolve_target("192.0.2.5", family="ipv6")


def test_resolve_target_auto_prefers_ipv4(monkeypatch):
    records = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::9", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.9", 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: records)
    assert scanner.resolve_target("dual.example") == "192.0.2.9"


def test_resolve_target_can_force_ipv6(monkeypatch):
    captured = {}

    def fake_getaddrinfo(host, port, family, socktype):
        captured.update(host=host, port=port, family=family, socktype=socktype)
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 0, 0, 0))
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert scanner.resolve_target("v6.example", family="ipv6") == "2001:db8::10"
    assert captured["family"] == socket.AF_INET6


def test_http_host_header_brackets_ipv6_literals():
    assert scanner.http_host_header("2001:db8::1", 80) == "[2001:db8::1]"
    assert scanner.http_host_header("[2001:db8::1]", 8080) == "[2001:db8::1]:8080"
    assert scanner.http_host_header("2001:db8::1", 443, secure=True) == "[2001:db8::1]"


class RecordingSocket:
    def __init__(self):
        self.timeout = None
        self.endpoint = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, endpoint):
        self.endpoint = endpoint


def test_connect_probe_uses_ipv6_socket_and_endpoint(monkeypatch):
    created = {}
    fake = RecordingSocket()

    def factory(family, socktype):
        created["family"] = family
        created["socktype"] = socktype
        return fake

    monkeypatch.setattr(connect_scan.socket, "socket", factory)
    result = connect_scan._connect_probe("2001:db8::1", 443, 0.25)

    assert result["state"] == "open"
    assert created == {"family": socket.AF_INET6, "socktype": socket.SOCK_STREAM}
    assert fake.endpoint == ("2001:db8::1", 443, 0, 0)


def test_build_syn_packets_uses_ipv6_layer(monkeypatch):
    ipv4_layer = object()
    ipv6_layer = object()
    tcp_layer = object()

    class FakePacket:
        def __init__(self, layers):
            self.layers = list(layers)

        def __truediv__(self, other):
            if isinstance(other, FakePacket):
                return FakePacket(self.layers + other.layers)
            return FakePacket(self.layers + [other])

        def haslayer(self, layer):
            return any(item[0] is layer for item in self.layers)

        def __getitem__(self, layer):
            for layer_type, value in self.layers:
                if layer_type is layer:
                    return value
            raise KeyError(layer)

    class LayerFactory:
        def __init__(self, layer_type):
            self.layer_type = layer_type

        def __call__(self, **kwargs):
            return FakePacket([(self.layer_type, SimpleNamespace(**kwargs))])

    monkeypatch.setattr(synscan, "IP", LayerFactory(ipv4_layer), raising=False)
    monkeypatch.setattr(synscan, "IPv6", LayerFactory(ipv6_layer), raising=False)
    monkeypatch.setattr(synscan, "TCP", LayerFactory(tcp_layer), raising=False)

    packet = scanner.build_syn_packets("2001:db8::1", [443])[0]
    assert packet.haslayer(ipv6_layer)
    assert not packet.haslayer(ipv4_layer)
    assert packet[tcp_layer].dport == 443


def test_classify_icmpv6_error_as_filtered(monkeypatch):
    tcp_layer = object()
    icmp_layer = object()
    icmpv6_layer = object()

    class FakeResponse:
        def haslayer(self, layer):
            return layer is icmpv6_layer

        def __getitem__(self, layer):
            if layer is icmpv6_layer:
                return SimpleNamespace(type=1, code=1)
            raise KeyError(layer)

    monkeypatch.setattr(synscan, "TCP", tcp_layer, raising=False)
    monkeypatch.setattr(synscan, "ICMP", icmp_layer, raising=False)
    monkeypatch.setattr(synscan, "ICMPV6_ERROR_LAYERS", (icmpv6_layer,))

    state, reason = scanner.classify_syn_response(FakeResponse())
    assert state == "filtered"
    assert reason == "ICMPv6 type 1 code 1"


def test_json_and_csv_reports_record_ipv6_family(tmp_path):
    started = datetime(2026, 7, 18, tzinfo=timezone.utc)
    result = [scanner.make_result(443, "open", "SYN-ACK", service="HTTPS")]
    json_path = tmp_path / "v6.json"
    csv_path = tmp_path / "v6.csv"

    scanner.write_report(
        json_path,
        "2001:db8::1",
        "2001:db8::1",
        result,
        0.5,
        "TCP connect scan (socket)",
        started,
        started,
    )
    scanner.write_report(
        csv_path,
        "2001:db8::1",
        "2001:db8::1",
        result,
        0.5,
        "TCP connect scan (socket)",
        started,
        started,
    )

    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["target"]["address_family"] == "IPv6"
    assert "address_family" in csv_path.read_text(encoding="utf-8").splitlines()[0]
    assert "IPv6" in csv_path.read_text(encoding="utf-8")


def test_parser_exposes_mutually_exclusive_family_flags():
    parser = scanner.build_parser()
    assert parser.parse_args(["::1", "-6"]).ipv6 is True
    assert parser.parse_args(["127.0.0.1", "-4"]).ipv4 is True
    with pytest.raises(SystemExit):
        parser.parse_args(["localhost", "-4", "-6"])


def test_main_passes_ipv6_preference_to_resolver(monkeypatch, capsys):
    captured = {}

    def fake_resolve(target, family="auto"):
        captured["target"] = target
        captured["family"] = family
        return "2001:db8::20"

    monkeypatch.setattr(net, "resolve_target", fake_resolve)
    monkeypatch.setattr(scanner, "parse_ports", lambda _spec: [80])
    monkeypatch.setattr(
        scanner,
        "tcp_connect_scan",
        lambda *_a, **_k: [scanner.make_result(80, "closed", "refused")],
    )
    monkeypatch.setattr(scanner, "print_results", lambda *_a, **_k: None)
    monkeypatch.setattr(scanner.time, "perf_counter", lambda: 10.0)
    monkeypatch.setattr(sys, "argv", ["portscan", "v6.example", "-6", "--no-banner"])

    assert scanner.main() == 0
    assert captured == {"target": "v6.example", "family": "ipv6"}
    assert "Family: IPv6" in capsys.readouterr().out
