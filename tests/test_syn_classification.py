from types import SimpleNamespace

import port_scanner as scanner


TCP_LAYER = object()
ICMP_LAYER = object()


class FakeResponse:
    def __init__(self, tcp=None, icmp=None):
        self.tcp = tcp
        self.icmp = icmp

    def haslayer(self, layer):
        if layer is TCP_LAYER:
            return self.tcp is not None
        if layer is ICMP_LAYER:
            return self.icmp is not None
        return False

    def __getitem__(self, layer):
        if layer is TCP_LAYER:
            return self.tcp
        if layer is ICMP_LAYER:
            return self.icmp
        raise KeyError(layer)


def install_layers(monkeypatch):
    monkeypatch.setattr(scanner, "TCP", TCP_LAYER, raising=False)
    monkeypatch.setattr(scanner, "ICMP", ICMP_LAYER, raising=False)


def test_syn_ack_is_open(monkeypatch):
    install_layers(monkeypatch)
    response = FakeResponse(tcp=SimpleNamespace(flags=0x12))
    assert scanner.classify_syn_response(response) == ("open", "SYN-ACK")


def test_rst_is_closed(monkeypatch):
    install_layers(monkeypatch)
    response = FakeResponse(tcp=SimpleNamespace(flags=0x04))
    assert scanner.classify_syn_response(response) == ("closed", "RST")


def test_icmp_response_is_filtered(monkeypatch):
    install_layers(monkeypatch)
    response = FakeResponse(icmp=SimpleNamespace(type=3, code=13))
    assert scanner.classify_syn_response(response) == (
        "filtered",
        "ICMP type 3 code 13",
    )


def test_unexpected_tcp_flags_are_filtered(monkeypatch):
    install_layers(monkeypatch)
    response = FakeResponse(tcp=SimpleNamespace(flags=0x10))
    state, reason = scanner.classify_syn_response(response)
    assert state == "filtered"
    assert "unexpected TCP flags" in reason


def test_unexpected_non_tcp_response_is_filtered(monkeypatch):
    install_layers(monkeypatch)
    assert scanner.classify_syn_response(FakeResponse()) == (
        "filtered",
        "unexpected response",
    )


class FakeSent:
    def __init__(self, port, sport):
        self.layer = SimpleNamespace(dport=port, sport=sport)

    def __getitem__(self, layer):
        assert layer is TCP_LAYER
        return self.layer


def test_syn_scan_retries_unanswered_ports_without_sending_packets(monkeypatch):
    install_layers(monkeypatch)
    monkeypatch.setattr(scanner, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(scanner, "conf", SimpleNamespace(verb=1), raising=False)

    sent_by_port = {
        22: FakeSent(22, 40022),
        80: FakeSent(80, 40080),
    }
    monkeypatch.setattr(
        scanner,
        "build_syn_packets",
        lambda _ip, ports: [sent_by_port[port] for port in ports],
    )

    calls = []

    def fake_sr(packets, **kwargs):
        calls.append((list(packets), kwargs))
        if len(calls) == 1:
            return (
                [(sent_by_port[22], FakeResponse(tcp=SimpleNamespace(flags=0x04)))],
                [sent_by_port[80]],
            )
        return (
            [(sent_by_port[80], FakeResponse(tcp=SimpleNamespace(flags=0x04)))],
            [],
        )

    monkeypatch.setattr(scanner, "sr", fake_sr, raising=False)
    monkeypatch.setattr(scanner, "send", lambda *_a, **_k: None, raising=False)

    results = scanner.syn_scan(
        "192.0.2.1",
        [22, 80],
        timeout=0.1,
        batch_size=64,
        retries=1,
        inter=0.001,
        progress=False,
    )

    assert [result["state"] for result in results] == ["closed", "closed"]
    assert len(calls) == 2
    assert calls[1][1]["inter"] == 0.002


def test_syn_scan_marks_persistent_no_response_filtered(monkeypatch, capsys):
    install_layers(monkeypatch)
    monkeypatch.setattr(scanner, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(scanner, "conf", SimpleNamespace(verb=1), raising=False)
    sent = FakeSent(22, 40022)
    monkeypatch.setattr(scanner, "build_syn_packets", lambda *_a, **_k: [sent])
    monkeypatch.setattr(scanner, "sr", lambda packets, **_k: ([], packets), raising=False)
    monkeypatch.setattr(scanner, "send", lambda *_a, **_k: None, raising=False)

    results = scanner.syn_scan(
        "192.0.2.1", [22], timeout=0.1, retries=0, progress=False
    )

    assert results[0]["state"] == "filtered"
    assert "no response after 1 attempt" in results[0]["reason"]
    assert "target returned no replies" in capsys.readouterr().out
