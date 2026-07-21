import errno
import socket

import port_scanner as scanner
from portscanner import connect_scan


class FakeSocket:
    def __init__(self, outcome=None):
        self.outcome = outcome
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        if self.outcome is not None:
            raise self.outcome


def install_socket_factory(monkeypatch, outcomes):
    queue = list(outcomes)

    def factory(*_args, **_kwargs):
        return FakeSocket(queue.pop(0))

    monkeypatch.setattr(connect_scan.socket, "socket", factory)


def test_connect_probe_classifies_success_as_open(monkeypatch):
    install_socket_factory(monkeypatch, [None])
    result = scanner._connect_probe("192.0.2.1", 80, 0.1)
    assert result["state"] == "open"


def test_connect_probe_classifies_refusal_as_closed(monkeypatch):
    install_socket_factory(monkeypatch, [ConnectionRefusedError()])
    result = scanner._connect_probe("192.0.2.1", 80, 0.1)
    assert result["state"] == "closed"


def test_connect_probe_classifies_timeout_as_filtered(monkeypatch):
    install_socket_factory(monkeypatch, [socket.timeout()])
    result = scanner._connect_probe("192.0.2.1", 22, 0.1)
    assert result["state"] == "filtered"
    assert result["reason"] == "timeout"


def test_connect_probe_retries_ambiguous_error_then_succeeds(monkeypatch):
    install_socket_factory(
        monkeypatch,
        [OSError(errno.EAGAIN, "try again"), None],
    )
    monkeypatch.setattr(connect_scan.time, "sleep", lambda _seconds: None)
    result = scanner._connect_probe("192.0.2.1", 22, 0.1, retries=1)
    assert result["state"] == "open"


def test_connect_probe_reports_persistent_resource_exhaustion(monkeypatch):
    install_socket_factory(
        monkeypatch,
        [OSError(errno.EMFILE, "too many files"), OSError(errno.EMFILE, "too many files")],
    )
    monkeypatch.setattr(connect_scan.time, "sleep", lambda _seconds: None)
    result = scanner._connect_probe("192.0.2.1", 80, 0.1, retries=1)
    assert result["state"] == "error"
    assert "local scanner resource error" in result["reason"]


def test_tcp_connect_scan_sorts_results(monkeypatch):
    def fake_probe(_ip, port, _timeout, _retries):
        state = "open" if port == 80 else "closed"
        return scanner.make_result(port, state, "test")

    monkeypatch.setattr(connect_scan, "_connect_probe", fake_probe)
    results = scanner.tcp_connect_scan(
        "192.0.2.1", [443, 22, 80], max_threads=2, progress=False
    )
    assert [result["port"] for result in results] == [22, 80, 443]
