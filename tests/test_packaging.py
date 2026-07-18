from pathlib import Path
import shutil
from importlib import metadata
import subprocess
import sys

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

import port_scanner as legacy_module
import portscanner
from portscanner import cli


ROOT = Path(__file__).resolve().parents[1]


def run_command(arguments):
    return subprocess.run(
        arguments,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_package_and_scanner_versions_agree():
    assert portscanner.__version__ == "5.0"
    assert cli.SCANNER_VERSION == portscanner.__version__


def test_installed_distribution_version_matches_package():
    assert metadata.version("python-port-scanner") == portscanner.__version__


def test_legacy_import_aliases_real_implementation():
    assert legacy_module is cli
    assert legacy_module.main is cli.main


def test_pyproject_defines_console_entry_point_and_src_layout():
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)

    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "portscanner.__version__"
    }
    assert project["project"]["scripts"]["portscan"] == (
        "portscanner.cli:console_main"
    )
    assert project["tool"]["setuptools"]["package-dir"] == {"": "src"}


def test_installed_portscan_command_is_available():
    executable = Path(sys.executable).with_name("portscan")
    assert executable.exists() or shutil.which("portscan")

    completed = run_command([str(executable), "--version"])
    assert completed.returncode == 0
    assert completed.stdout.strip().endswith("5.0")


def test_package_module_entry_point():
    completed = run_command([sys.executable, "-m", "portscanner", "--help"])
    assert completed.returncode == 0
    assert "--profile {fast,balanced,reliable}" in completed.stdout


def test_legacy_launcher_remains_supported():
    completed = run_command([sys.executable, "port_scanner.py", "--version"])
    assert completed.returncode == 0
    assert completed.stdout.strip().endswith("5.0")
