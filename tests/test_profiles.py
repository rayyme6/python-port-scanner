from argparse import Namespace

import pytest

import port_scanner as scanner


@pytest.mark.parametrize(
    ("profile", "expected"),
    [
        (
            "fast",
            {
                "timeout": 0.5,
                "threads": 200,
                "batch_size": 1024,
                "inter": 0.0,
                "retries": 0,
            },
        ),
        (
            "balanced",
            {
                "timeout": 1.0,
                "threads": 100,
                "batch_size": 512,
                "inter": 0.001,
                "retries": 1,
            },
        ),
        (
            "reliable",
            {
                "timeout": 1.5,
                "threads": 50,
                "batch_size": 256,
                "inter": 0.003,
                "retries": 2,
            },
        ),
    ],
)
def test_profiles_resolve_to_expected_settings(profile, expected):
    args = scanner.build_parser().parse_args(["localhost", "--profile", profile])
    settings, overrides = scanner.resolve_scan_settings(args)
    assert settings == expected
    assert overrides == []


def test_explicit_values_override_selected_profile():
    args = scanner.build_parser().parse_args(
        [
            "localhost",
            "--profile",
            "reliable",
            "--timeout",
            "2",
            "--threads",
            "80",
            "--batch-size",
            "128",
            "--inter",
            "0.01",
            "--retries",
            "4",
        ]
    )

    settings, overrides = scanner.resolve_scan_settings(args)

    assert settings == {
        "timeout": 2.0,
        "threads": 80,
        "batch_size": 128,
        "inter": 0.01,
        "retries": 4,
    }
    assert overrides == ["timeout", "threads", "batch_size", "inter", "retries"]


def test_only_explicit_values_are_reported_as_overrides():
    args = scanner.build_parser().parse_args(
        ["localhost", "--profile", "fast", "--timeout", "3"]
    )
    settings, overrides = scanner.resolve_scan_settings(args)
    assert settings["timeout"] == 3.0
    assert settings["threads"] == 200
    assert overrides == ["timeout"]


def test_profile_resolution_returns_an_independent_dictionary():
    args = scanner.build_parser().parse_args(["localhost", "--profile", "fast"])
    settings, _ = scanner.resolve_scan_settings(args)
    settings["threads"] = 1
    assert scanner.SCAN_PROFILES["fast"]["threads"] == 200


def test_resolve_scan_settings_rejects_unknown_profile_without_argparse():
    args = Namespace(profile="unknown")
    with pytest.raises(ValueError, match="unknown scan profile"):
        scanner.resolve_scan_settings(args)


def test_normalized_scan_settings_uses_balanced_fallback_and_stable_types():
    settings = scanner.normalized_scan_settings({"timeout": 2, "retries": 3.0})
    assert settings == {
        "timeout": 2.0,
        "threads": 100,
        "batch_size": 512,
        "inter": 0.001,
        "retries": 3,
    }


def test_format_scan_settings_shows_engine_relevant_values():
    settings = scanner.SCAN_PROFILES["reliable"]
    assert scanner.format_scan_settings(settings, syn=False) == (
        "timeout=1.5s, retries=2, threads=50"
    )
    assert scanner.format_scan_settings(settings, syn=True) == (
        "timeout=1.5s, retries=2, batch-size=256, inter=0.003s"
    )
