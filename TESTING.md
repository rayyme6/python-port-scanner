# Testing

Create and activate a virtual environment, then install the project and its
development tools in editable mode:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Verify all three supported launch methods:

```bash
portscan --help
python -m portscanner --help
python port_scanner.py --help
```

Run the complete suite:

```bash
python -m pytest tests -v
```

Run coverage enforcement against the installed package:

```bash
python -m pytest tests \
  --cov=portscanner \
  --cov-report=term-missing \
  --cov-fail-under=75
```

Build the wheel and source distribution:

```bash
python -m build
```

The automated tests are network-free. IPv4/IPv6 resolution, socket endpoints,
HTTP Host headers, TLS sessions, Scapy IPv4/IPv6 packet selection, ICMP/ICMPv6
responses, thread-pool futures, interruptions, and report writers are mocked or
constructed locally.

The v4.7 suite contains 151 tests and enforces at least 75% package coverage.
A local manual IPv6 smoke test can be run without scanning another device:

```bash
python -m http.server 8765 --bind ::1
# In another terminal:
portscan ::1 -p 8765
```
