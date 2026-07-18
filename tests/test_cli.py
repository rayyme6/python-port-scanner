from pathlib import Path
import subprocess
import sys

import pytest

import port_scanner as scanner


SCRIPT = Path(__file__).resolve().parents[1] / "port_scanner.py"


def test_parser_defaults():
    args = scanner.build_parser().parse_args(["localhost"])
    settings, overrides = scanner.resolve_scan_settings(args)

    assert args.ports == "1-1024"
    assert args.profile == "balanced"
    assert args.timeout is None
    assert args.threads is None
    assert args.batch_size is None
    assert args.inter is None
    assert args.retries is None
    assert settings == scanner.SCAN_PROFILES["balanced"]
    assert overrides == []
    assert args.banner_threads == 10
    assert args.output_format == "auto"
    assert args.report_open_only is False


@pytest.mark.parametrize(
    "arguments",
    [
        ["localhost", "--threads", "0"],
        ["localhost", "--timeout", "0"],
        ["localhost", "--retries", "-1"],
        ["localhost", "--output-format", "xml"],
        ["localhost", "--profile", "reckless"],
    ],
)
def test_parser_rejects_invalid_option_values(arguments):
    with pytest.raises(SystemExit) as exc_info:
        scanner.build_parser().parse_args(arguments)
    assert exc_info.value.code == 2


def test_help_command_is_a_network_free_smoke_test():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "--output-format" in completed.stdout
    assert "--banner-threads" in completed.stdout
    assert "--profile {fast,balanced,reliable}" in completed.stdout


def test_invalid_port_spec_returns_argparse_error_without_scanning():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "localhost", "-p", "invalid"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 2
    assert "invalid port or range" in completed.stderr
