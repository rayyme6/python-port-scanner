import socket

import pytest

import port_scanner as scanner


class FakeSocket:
    def __init__(self, recv_chunks=(), connect_error=None):
        self.recv_chunks = list(recv_chunks)
        self.connect_error = connect_error
        self.sent = []
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        if self.connect_error:
            raise self.connect_error

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _size):
        if not self.recv_chunks:
            return b""
        item = self.recv_chunks.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class FakeTLS(FakeSocket):
    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_TEST_CIPHER", "TLSv1.3", 256)

    def getpeercert(self, binary_form=False):
        assert binary_form is True
        return b"certificate"


class FakeTLSContext:
    def __init__(self, tls_socket, capture):
        self.tls_socket = tls_socket
        self.capture = capture
        self.check_hostname = None
        self.verify_mode = None

    def wrap_socket(self, raw_socket, server_hostname=None):
        self.capture["raw_socket"] = raw_socket
        self.capture["server_hostname"] = server_hostname
        return self.tls_socket


def test_receive_response_stops_after_headers():
    sock = FakeSocket([b"HTTP/1.1 200 OK\r\n", b"Server: test\r\n\r\n", b"body"])
    data = scanner.receive_response(sock)
    assert data.endswith(b"\r\n\r\n")
    assert b"body" not in data


def test_receive_response_tolerates_timeout():
    sock = FakeSocket([b"partial", socket.timeout()])
    assert scanner.receive_response(sock) == b"partial"


def test_probe_tls_detects_https_and_uses_sni(monkeypatch):
    raw = FakeSocket()
    tls = FakeTLS([b"HTTP/1.0 200 OK\r\nServer: test-server\r\n\r\n"])
    capture = {}

    monkeypatch.setattr(scanner.socket, "create_connection", lambda *_a, **_k: raw)
    monkeypatch.setattr(
        scanner.ssl,
        "SSLContext",
        lambda _protocol: FakeTLSContext(tls, capture),
    )
    monkeypatch.setattr(scanner, "decode_certificate", lambda *_a, **_k: ["CN=example.test"])

    service, banner = scanner.probe_tls(
        "example.test", "192.0.2.1", 4443, 1.0, probe_https=True
    )

    assert service == "HTTPS"
    assert "test-server" in banner
    assert "TLSv1.3" in banner
    assert "TLS_TEST_CIPHER" in banner
    assert "CN=example.test" in banner
    assert capture["server_hostname"] == "example.test"
    assert tls.sent[0].startswith(b"GET / HTTP/1.0")


def test_probe_tls_omits_sni_for_ip_literal(monkeypatch):
    raw = FakeSocket()
    tls = FakeTLS()
    capture = {}
    monkeypatch.setattr(scanner.socket, "create_connection", lambda *_a, **_k: raw)
    monkeypatch.setattr(scanner.ssl, "SSLContext", lambda _p: FakeTLSContext(tls, capture))
    monkeypatch.setattr(scanner, "decode_certificate", lambda *_a, **_k: [])

    service, banner = scanner.probe_tls("127.0.0.1", "127.0.0.1", 443, 1.0)
    assert service == "HTTPS"
    assert "TLSv1.3" in banner
    assert capture["server_hostname"] is None


def test_identify_service_uses_tls_probe_on_tls_port(monkeypatch):
    monkeypatch.setattr(scanner, "probe_tls", lambda *_a, **_k: ("HTTPS", "TLS details"))
    assert scanner.identify_service("example.test", "192.0.2.1", 443, 1.0) == (
        "HTTPS",
        "TLS details",
    )


def test_identify_service_reports_tls_handshake_failure(monkeypatch):
    def fail(*_args, **_kwargs):
        raise scanner.ssl.SSLError("bad handshake")

    monkeypatch.setattr(scanner, "probe_tls", fail)
    assert scanner.identify_service("example.test", "192.0.2.1", 443, 1.0) == (
        "HTTPS",
        "TLS handshake failed",
    )


def test_identify_service_recognizes_passive_http(monkeypatch):
    sock = FakeSocket([b"HTTP/1.1 200 OK\r\nServer: passive-http\r\n\r\n"])
    monkeypatch.setattr(scanner.socket, "socket", lambda *_a, **_k: sock)
    assert scanner.identify_service("router.local", "192.0.2.1", 80, 1.0) == (
        "HTTP",
        "passive-http",
    )


def test_identify_service_recognizes_passive_ssh(monkeypatch):
    sock = FakeSocket([b"SSH-2.0-UnitTest\r\n"])
    monkeypatch.setattr(scanner.socket, "socket", lambda *_a, **_k: sock)
    assert scanner.identify_service("host.local", "192.0.2.2", 22, 1.0) == (
        "SSH",
        "SSH-2.0-UnitTest",
    )


def test_identify_service_tries_tls_on_unknown_silent_port(monkeypatch):
    silent = FakeSocket([socket.timeout()])
    monkeypatch.setattr(scanner.socket, "socket", lambda *_a, **_k: silent)
    monkeypatch.setattr(scanner, "probe_tls", lambda *_a, **_k: ("TLS", "TLSv1.3"))
    assert scanner.identify_service("host.local", "192.0.2.2", 4444, 1.0) == (
        "TLS",
        "TLSv1.3",
    )


def test_identify_service_plain_http_fallback(monkeypatch):
    silent = FakeSocket([socket.timeout()])
    http = FakeSocket([b"HTTP/1.0 404 Not Found\r\n\r\n"])
    monkeypatch.setattr(scanner.socket, "socket", lambda *_a, **_k: silent)
    monkeypatch.setattr(scanner.socket, "create_connection", lambda *_a, **_k: http)

    assert scanner.identify_service("router.local", "192.0.2.1", 80, 1.0) == (
        "HTTP",
        "HTTP/1.0 404 Not Found",
    )
    assert http.sent[0].startswith(b"HEAD / HTTP/1.0")


def test_identify_open_services_updates_open_rows_only(monkeypatch):
    results = [
        scanner.make_result(22, "closed", "connection refused"),
        scanner.make_result(80, "open", "connection succeeded"),
        scanner.make_result(443, "open", "connection succeeded"),
    ]

    def identify(_target, _ip, port, _timeout):
        return ("HTTP" if port == 80 else "HTTPS", f"banner-{port}")

    monkeypatch.setattr(scanner, "identify_service", identify)
    scanner.identify_open_services(
        "example.test", "192.0.2.1", results, 1.0, max_workers=2, progress=False
    )

    assert results[0]["service"] == "unknown"
    assert results[1]["service"] == "HTTP"
    assert results[1]["banner"] == "banner-80"
    assert results[2]["service"] == "HTTPS"


def test_identify_open_services_returns_immediately_without_open_ports(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "identify_service",
        lambda *_a, **_k: pytest.fail("should not be called"),
    )
    scanner.identify_open_services(
        "example.test",
        "192.0.2.1",
        [scanner.make_result(80, "closed", "refused")],
        1.0,
        progress=False,
    )
