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

The tests are network-free. Sockets, TLS sessions, Scapy responses,
thread-pool futures, interruptions, and report writers are mocked or
constructed locally.
