import pytest

import port_scanner as scanner


def test_strip_telnet_negotiation_removes_iac_sequences():
    payload = b"\xff\xfb\x01Welcome\r\n\xff\xfd\x03"
    assert scanner.strip_telnet_negotiation(payload) == b"Welcome\r\n"


def test_strip_telnet_negotiation_preserves_escaped_ff():
    assert scanner.strip_telnet_negotiation(b"A\xff\xffB") == b"A\xffB"


def test_readable_banner_returns_first_nonempty_line():
    data = b"\r\n  SSH-2.0-Test_Server  \r\nignored"
    assert scanner.readable_banner(data, 22) == "SSH-2.0-Test_Server"


def test_readable_banner_reports_telnet_negotiation_only():
    assert scanner.readable_banner(b"\xff\xfb\x01", 23) == "Telnet negotiation received"


def test_readable_banner_reports_binary_payload():
    assert scanner.readable_banner(b"\x00\x01\x02", 9999) == "binary response (3 bytes)"


def test_http_host_header_omits_default_port():
    assert scanner.http_host_header("example.test", 80, secure=False) == "example.test"
    assert scanner.http_host_header("example.test", 443, secure=True) == "example.test"


def test_http_host_header_keeps_nondefault_port():
    assert scanner.http_host_header("example.test", 8080, secure=False) == "example.test:8080"
    assert scanner.http_host_header("example.test", 4443, secure=True) == "example.test:4443"


def test_build_http_request_preserves_hostname_and_version():
    request = scanner.build_http_request("example.test", 8443, secure=True, method="GET")
    text = request.decode("ascii")
    assert text.startswith("GET / HTTP/1.0\r\n")
    assert "Host: example.test:8443\r\n" in text
    assert f"User-Agent: {scanner.SCANNER_NAME}/{scanner.SCANNER_VERSION}\r\n" in text


def test_build_http_request_rejects_unsupported_method():
    with pytest.raises(ValueError, match="unsupported HTTP probe method"):
        scanner.build_http_request("example.test", 80, method="POST")


def test_http_response_banner_prefers_server_header():
    data = b"HTTP/1.1 200 OK\r\nServer: unit-test/1.0\r\n\r\n"
    assert scanner.http_response_banner(data) == "unit-test/1.0"


def test_http_response_banner_falls_back_to_status_line():
    data = b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    assert scanner.http_response_banner(data) == "HTTP/1.0 404 Not Found"


def test_http_response_banner_rejects_non_http_data():
    assert scanner.http_response_banner(b"SSH-2.0-test\r\n") == ""
