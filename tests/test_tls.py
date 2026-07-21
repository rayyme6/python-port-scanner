import hashlib

import pytest

import port_scanner as scanner
from portscanner import service_id


def certificate(*, common_name="", dns_names=(), ip_names=()):
    subject = ((('commonName', common_name),),) if common_name else ()
    sans = tuple(("DNS", value) for value in dns_names)
    sans += tuple(("IP Address", value) for value in ip_names)
    return {"subject": subject, "subjectAltName": sans}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("[::1]", True),
        ("example.test", False),
    ],
)
def test_is_ip_literal(value, expected):
    assert scanner.is_ip_literal(value) is expected


def test_dns_pattern_matches_exact_case_insensitively():
    assert scanner.dns_pattern_matches("EXAMPLE.TEST.", "example.test")


def test_dns_pattern_matches_one_label_wildcard_only():
    assert scanner.dns_pattern_matches("*.example.test", "api.example.test")
    assert not scanner.dns_pattern_matches("*.example.test", "deep.api.example.test")
    assert not scanner.dns_pattern_matches("f*o.example.test", "foo.example.test")


def test_certificate_matching_prefers_dns_san_over_common_name():
    decoded = certificate(common_name="correct.test", dns_names=("wrong.test",))
    assert scanner.certificate_matches_hostname(decoded, "correct.test") is False


def test_certificate_matching_uses_common_name_without_san():
    decoded = certificate(common_name="router.local")
    assert scanner.certificate_matches_hostname(decoded, "router.local") is True


def test_certificate_matching_supports_dns_wildcards():
    decoded = certificate(dns_names=("*.example.test",))
    assert scanner.certificate_matches_hostname(decoded, "api.example.test") is True


def test_certificate_matching_requires_ip_san_for_ip_target():
    decoded = certificate(common_name="127.0.0.1")
    assert scanner.certificate_matches_hostname(decoded, "127.0.0.1") is False


def test_certificate_matching_accepts_matching_ip_san():
    decoded = certificate(ip_names=("127.0.0.1",))
    assert scanner.certificate_matches_hostname(decoded, "127.0.0.1") is True


def test_certificate_matching_returns_none_without_input():
    assert scanner.certificate_matches_hostname({}, "example.test") is None
    assert scanner.certificate_matches_hostname(certificate(common_name="x"), "") is None


def test_decode_certificate_falls_back_to_sha256(monkeypatch):
    der = b"not-a-real-certificate"

    def fail_conversion(_value):
        raise ValueError("invalid")

    monkeypatch.setattr(service_id.ssl, "DER_cert_to_PEM_cert", fail_conversion)
    expected = hashlib.sha256(der).hexdigest()[:16]
    assert scanner.decode_certificate(der, "example.test") == [f"cert SHA256 {expected}"]
