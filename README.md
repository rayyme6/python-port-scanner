# Python Port Scanner

A command-line IPv4/IPv6 TCP port scanner written in Python for learning network programming, conducting authorized security assessments, and troubleshooting network services.

The scanner supports a multithreaded TCP connect mode and a rate-controlled, batched half-open SYN mode using Scapy. It can scan single hosts, multiple hosts, or whole CIDR ranges; identify services over plain banners, HTTP, and TLS; and export text, JSON, or CSV reports. It ships as an installable package with a `portscan` command, a 168-test suite, and a GitHub Actions CI pipeline.

> **Responsible use:** Only scan systems and networks that you own or have explicit permission to test.

---

## Features

* Multithreaded TCP connect scanning (no special privileges required)
* Rate-controlled, batched half-open TCP SYN scanning with Scapy (adaptive retry with shrinking batch size and growing timeout)
* IPv4 **and** IPv6 targets, including bracketed literals (`[2001:db8::1]`) and forced-family resolution (`-4` / `-6`)
* Single hosts, multiple hosts, or CIDR ranges in one invocation, plus `--targets-file` for reading targets from a file
* Safety limits (`--max-targets`, `--max-probes`) so a mistyped CIDR range can't accidentally launch a massive scan
* Individual ports, port ranges, and mixed port specifications
* Banner grabbing, generic HTTP probing, and TLS/HTTPS certificate inspection (subject, SAN/hostname matching, expiry) for service identification
* Three built-in tuning profiles (`fast`, `balanced`, `reliable`) plus per-parameter overrides
* Live progress display
* Text, JSON, and CSV report export (single-target and multi-target/batch reports)
* Graceful Ctrl+C handling — an interrupted scan still writes a report of whatever completed
* Detection of completely silent or unreachable targets
* No external dependency required for TCP connect scans; Scapy is only needed for `--syn`

---

## Scan Modes

| Mode             | Flag    | Library         | Privileges           | Description                                                                                                                    |
| ---------------- | ------- | --------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| TCP Connect scan | Default | Python `socket` | None                  | Completes the full TCP three-way handshake. Multithreaded, reliable, and works without administrative privileges.               |
| SYN scan         | `--syn` | Scapy           | Root / Administrator  | Sends batches of TCP SYN packets and examines the replies without completing the handshake. Unanswered ports are retried in shrinking batches with a growing timeout before being marked filtered. |

### TCP Connect Scan

The default scanner uses Python's socket library to attempt a complete TCP connection.

A port is considered open when the connection succeeds:

```text
Scanner → SYN
Target  → SYN-ACK
Scanner → ACK
```

Because a full connection is completed, the attempt may appear in the target service's connection logs.

### SYN Scan

The SYN scanner uses Scapy to create and send raw TCP packets in batches (IPv4 or IPv6).

Typical responses are interpreted as follows:

```text
SYN-ACK response  → Open
RST response      → Closed
No response       → Filtered, dropped, or unreachable (retried before being marked filtered)
ICMP response     → Network device or firewall responded
```

When a port returns a SYN-ACK, the scanner immediately sends a TCP reset packet:

```text
Scanner → SYN
Target  → SYN-ACK
Scanner → RST
```

This prevents the normal TCP handshake from being completed. Ports that don't answer the first batch are retried with a smaller batch size and a longer timeout — this is what makes the scanner tolerant of routers that drop bursts of packets.

> **Note:** Port discovery in SYN mode is half-open, but banner identification creates a normal TCP connection to each discovered open port. Use `--syn --no-banner` when you only want half-open port discovery.

---

## Requirements

* Python 3.10 or newer
* Linux or macOS for SYN scanning
* Scapy for SYN scanning (`pip install -e .`  pulls it in automatically)
* Root privileges for raw SYN packets

The TCP connect scanner only uses Python's standard library — no dependencies, no privileges.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/rayyme6/python-port-scanner.git
cd python-port-scanner
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the package (this also installs Scapy and registers the `portscan` command):

```bash
pip install -e .
```

For running the test suite too:

```bash
pip install -e ".[dev]"
```

---

## Usage

Basic syntax:

```bash
portscan TARGET [TARGET ...] [OPTIONS]
```

Display the complete help menu:

```bash
portscan --help
```

The original single-file entry point still works if you prefer it — `python3 port_scanner.py TARGET [OPTIONS]` is kept as a thin, fully supported alias for `portscan`.

---

## Examples

### Scan TCP ports 1 through 1024 (the default range)

```bash
portscan 192.168.1.10
```

This checks every TCP port from 1 through 1024 — not Nmap's list of the 1,024 most common ports.

### Scan specific ports, a range, or a mixture

```bash
portscan 192.168.1.10 -p 22,80,443
portscan 192.168.1.10 -p 1-5000
portscan 192.168.1.10 -p 22,80,443,8000-8100
```

### Scan a hostname, forcing IPv4 or IPv6

```bash
portscan example.com -p 80,443
portscan example.com -6 -p 22,80,443
```

### Scan multiple hosts or a whole CIDR range in one run

```bash
portscan 192.168.1.10 192.168.1.20 -p 22,80,443
portscan 192.168.1.0/28 -p 22,80,443
portscan 192.168.1.0/24 -p 80 --max-targets 254
```

### Read targets from a file

```bash
portscan --targets-file targets.txt -p 1-1024
```

### Use a tuning profile, or override individual settings

```bash
portscan 192.168.1.10 --profile fast
portscan 192.168.1.10 -p 1-5000 --threads 100
portscan 192.168.1.10 -p 1-1024 --timeout 0.5
```

A shorter timeout scans faster but may miss slow responses; a longer timeout is more reliable on slow networks but takes longer.

### Perform a SYN scan

```bash
sudo .venv/bin/portscan 192.168.1.10 -p 1-1024 --syn
sudo .venv/bin/portscan 192.168.1.0/29 --syn --profile reliable
```

Raw packet creation normally requires root privileges — see [Virtual Environment and `sudo`](#virtual-environment-and-sudo) below for why the full `.venv/bin/portscan` path matters.

### Skip banner/service identification

```bash
portscan 192.168.1.10 -p 1-65535 --no-banner
sudo .venv/bin/portscan 192.168.1.10 -p 1-1024 --syn --no-banner
```

This can make the scan faster when only open port numbers are required.

### Save a report as text, JSON, or CSV

```bash
portscan 192.168.1.10 -p 1-1024 -o report.txt
portscan 192.168.1.0/24 -p 1-1024 -o subnet.json
portscan 192.168.1.10 -p 1-1024 -o report.csv --report-open-only
```

The format is inferred from the file extension (`--output-format` overrides this). Reports include the target, resolved address, scan type, timestamps, duration, effective scan settings, and per-port state/service/banner rows.

---

## Command-Line Options

| Argument                        | Purpose                                                              |
| -------------------------------- | --------------------------------------------------------------------- |
| `TARGET [TARGET ...]`            | One or more IPv4/IPv6 addresses, hostnames, or CIDR ranges           |
| `--targets-file FILE`            | Read targets/CIDRs from FILE; may be supplied more than once         |
| `--max-targets`                  | Maximum expanded unique targets (default: 256)                       |
| `--max-probes`                   | Maximum target-port combinations (default: 1,000,000)                |
| `-4`, `--ipv4`                   | Resolve hostnames to IPv4 only                                       |
| `-6`, `--ipv6`                   | Resolve hostnames to IPv6 only                                       |
| `-p`, `--ports`                  | Ports such as `22,80,443` or `1-1024` (default: `1-1024`)            |
| `--profile`                      | Scan tuning preset: `fast`, `balanced`, `reliable` (default: `balanced`) |
| `-t`, `--timeout`                | Override the profile timeout in seconds                              |
| `--threads`                      | Override profile connect-scan worker threads                         |
| `--syn`                          | Use rate-controlled half-open SYN scanning through Scapy             |
| `--batch-size`                   | Override profile initial SYN packets per batch                       |
| `--inter`                        | Override profile delay between SYN packets, in seconds               |
| `--retries`                      | Override profile retry count for unanswered/transient probes         |
| `--no-banner`                    | Skip service, HTTP, and TLS identification                           |
| `--banner-threads`               | Concurrent service-identification workers (default: 10)              |
| `--show-all`                     | Display closed, filtered, and error states in the terminal           |
| `--no-progress`                  | Disable the live progress display                                    |
| `-o`, `--output`                 | Write a complete report, or partial results after Ctrl+C             |
| `--output-format`                | Report format: `auto`, `text`, `json`, `csv` (default: `auto` from filename extension) |
| `--report-open-only`             | Save only open ports instead of every scanned port's state           |
| `--version`                      | Show the installed version and exit                                  |
| `-h`, `--help`                   | Display the help menu                                                |

Default values:

```text
Ports:    1-1024
Profile:  balanced (timeout=1.0s, threads=100, batch-size=512, inter=0.001s, retries=1)
Mode:     TCP connect scan
```

---

## Example Output

```text
$ portscan 127.0.0.1 -p 22,80,8080,9000 --no-progress

Target: 127.0.0.1 (127.0.0.1)
Family: IPv4
Ports : 4
Mode  : TCP connect scan (socket)
Profile: balanced (overrides: none)
Tuning : timeout=1s, retries=1, threads=100

============================================================================
  Scan report for 127.0.0.1 (127.0.0.1)
  Scan type : TCP connect scan (socket)
  Duration  : 0.81s
  Summary   : 1 open, 3 closed, 0 filtered
============================================================================

  PORT    STATE      SERVICE           BANNER / REASON
  ------  --------   ---------------   ------------------------------------
  8080    open       HTTP              SimpleHTTP/0.6 Python/3.12.3

  Showing open ports only. Use --show-all for every state.
```

Every field above is a real, unedited run against a local HTTP server. With `-o report.json`, the same scan writes:

```json
{
  "scanner": { "name": "python-port-scanner", "version": "5.0" },
  "target": { "input": "127.0.0.1", "resolved_ip": "127.0.0.1", "address_family": "IPv4" },
  "scan": {
    "type": "TCP connect scan (socket)",
    "status": "completed",
    "duration_seconds": 0.805023,
    "profile": "balanced",
    "effective_settings": { "timeout": 1.0, "threads": 100, "batch_size": 512, "inter": 0.001, "retries": 1 }
  },
  "summary": { "open": 1, "closed": 0, "filtered": 0, "error": 0 },
  "results": [
    { "port": 8080, "state": "open", "service": "HTTP", "banner": "SimpleHTTP/0.6 Python/3.12.3", "reason": "connection succeeded" }
  ]
}
```

---

## How It Works

```text
Read command-line arguments
        ↓
Expand targets (single hosts, multiple hosts, CIDR ranges, --targets-file)
        ↓
Resolve each target to an IPv4/IPv6 address, enforcing --max-targets / --max-probes
        ↓
Parse and validate the port specification
        ↓
Select TCP connect or SYN scanning, using the chosen profile's settings
        ↓
Probe every requested port (Ctrl+C at any point preserves completed results)
        ↓
Attempt service, banner, HTTP, and TLS identification on open ports
        ↓
Print results, then optionally save a text/JSON/CSV report
```

---

## Port Parsing

The scanner accepts several port formats.

**Single port:** `80`
**Multiple ports:** `22,80,443`
**Port range:** `1-1024`
**Mixed:** `22,80,443,8000-8100`

Duplicate ports are automatically removed, and the final list is sorted. Valid port numbers range from 1 through 65535. Invalid examples: `0`, `65536`, `100-50`, `abc`.

---

## TCP Connect Scanning

The TCP connect scanner uses `socket.connect_ex()` to test each port over a thread pool, so many ports can be tested concurrently, over either IPv4 or IPv6.

**Open** — the connection succeeds and `connect_ex()` returns `0`.
**Closed** — the target actively refuses the connection; the host is reachable but nothing is listening on that port.
**No useful response** — the attempt times out or is silently dropped (firewall, offline host, wrong address, routing problem, timeout too short, or packet loss). Transient local errors (e.g. temporary resource exhaustion) are retried automatically before being reported.

---

## SYN Scanning

The SYN scanner uses Scapy to build IPv4 or IPv6 packets with a TCP layer:

```python
IP(dst=target_ip) / TCP(sport=source_port, dport=destination_port, flags="S")
```

Each packet uses a random high-numbered source port, the destination port under test, the SYN flag, and a random sequence number. Packets are sent in batches rather than one at a time; a batch that gets no replies is retried at a smaller size with a longer timeout, which is what lets the scanner tell "port is filtered" apart from "the network just dropped a whole burst of packets."

* **SYN-ACK response** → open. The scanner sends a RST to close the half-open connection without completing the handshake.
* **RST response** → closed.
* **No response** → filtered, dropped, or unreachable (only after retries are exhausted).
* **ICMP response** → a router, firewall, or the target itself responded with an error (message includes the ICMP type/code).

---

## Service and Banner Identification

After an open port is discovered, the scanner attempts service identification:

1. Assign a fallback service name based on the conventional port number.
2. Open a TCP connection to the port and wait briefly for the service to send a banner.
3. If nothing is received on a likely web port, send a generic HTTP `HEAD` request.
4. On likely TLS/HTTPS ports, attempt a TLS handshake and inspect the certificate (subject, SAN/hostname match, expiry) using only the Python standard library.
5. Examine whatever came back for a recognizable protocol.

Example banners:

```text
SSH-2.0-OpenSSH_9.6
220 FTP Server Ready
220 mail.example.com ESMTP
```

For silent web-like ports, the scanner sends a bare `HEAD / HTTP/1.0` request. A `404 Not Found` response is still evidence that an HTTP server accepted and processed the request — it does not indicate that the port is closed.

Service names based only on port numbers are best-effort labels, not definitive identification: an open port 23 is labelled `Telnet` because that's the conventional assignment, but another application could be listening there instead. The scanner does not perform full service-version fingerprinting the way `nmap -sV` does.

---

## Understanding Port States

**Open** — a program is accepting TCP connections on the port.
**Closed** — the host responded, but no program is accepting connections on the port.
**Filtered** — a firewall or network device may be blocking or silently dropping the probe.
**Unreachable or unresponsive** — the target may be offline, incorrectly addressed, separated by a routing problem, or protected by filtering.

By default the terminal view shows open ports only; pass `--show-all` to see every scanned state. Saved reports include every scanned port's state unless you pass `--report-open-only`.

---

## Completely Silent Targets

Both scanning engines track whether the target returned any response at all. An open-port response and an explicit rejection both confirm that something responded. If every probe times out with no replies, the scanner prints a warning instead of confidently reporting that the host has no open ports.

A completely silent result may mean the target is offline, changed IP address, is behind a firewall silently dropping packets, has wireless client isolation enabled, is on a different VLAN, has no route from the scanner, or that the timeout is simply too short. Useful troubleshooting commands: `ping -c 4 TARGET`, `ip route`, `ip neigh`, or checking your router's connected-device list.

---

## Virtual Environment and `sudo`

Installing the package (and Scapy) inside a virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Running `sudo portscan TARGET --syn` may use the root user's Python environment instead of your virtual environment, so root may be unable to find Scapy. Use the executable inside the virtual environment directly:

```bash
sudo .venv/bin/portscan TARGET --syn
```

This gives the command raw-socket privileges while still using the packages installed in `.venv`. Avoid installing packages globally with `sudo pip install scapy` — it can interfere with the operating system's managed Python environment.

---

## Testing

```bash
pip install -e ".[dev]"
pytest
```

The suite currently has 168 tests across 15 files covering port/target parsing, both scan engines (including interruption and retry behavior), TLS/certificate handling, service identification, all three report formats, and the CLI itself, with 84%+ coverage on the `portscanner` package. GitHub Actions runs the suite on Python 3.10 through 3.13 on every push and pull request.

---

## Project Structure

```text
python-port-scanner/
├── src/portscanner/
│   ├── __init__.py       # package version
│   ├── __main__.py       # `python -m portscanner` entry point
│   ├── cli.py             # argument parsing and scan orchestration
│   ├── net.py             # target/port parsing, DNS/CIDR resolution
│   ├── scan_result.py     # shared result model
│   ├── connect_scan.py    # TCP connect scan engine
│   ├── synscan.py         # Scapy-based SYN scan engine
│   ├── service_id.py      # banner/HTTP/TLS service identification
│   └── reports.py         # text/JSON/CSV report writers
├── port_scanner.py        # thin backward-compatible launcher
├── tests/                 # 168 tests across 15 files
├── .github/workflows/     # CI: pytest + coverage on Python 3.10-3.13
├── pyproject.toml         # packaging, console entry point, dev deps
├── requirements.txt
├── LICENSE                 # MIT
└── README.md
```

Each module in `src/portscanner/` is independently importable and independently tested; `cli.py` re-exports their public functions so existing imports of `portscanner.cli` keep working.

---

## Real-World Applications

This project can be used in authorized environments for network troubleshooting, verifying whether services are reachable, checking server exposure, testing firewall configurations, auditing home networks, validating cloud server security groups, post-deployment service verification, cybersecurity laboratory exercises, and learning socket programming, TCP packet structure, and TCP handshakes.

It is a learning and auditing tool, not an exploitation framework.

---

## Limitations

* TCP scanning only — no UDP scanning
* No operating-system fingerprinting
* No vulnerability detection or exploitation functionality
* Banner-based service identification, not full service-version fingerprinting (no `nmap -sV` equivalent)
* No historical comparison between scan results
* Generic HTTP/TLS probes are sent to silent open services on likely web/TLS ports; other silent services get no protocol-specific probe
* Banner-grabbing errors are intentionally suppressed rather than surfaced

---

## Possible Future Improvements

* UDP scanning
* Protocol-specific service probes beyond HTTP/TLS (e.g. SMTP, FTP command probing)
* Service-version fingerprinting
* Rate limiting tuned per-network rather than per-profile
* Previous-scan comparison / diffing
* Optional colored terminal output
* Operating-system fingerprinting
* Integration with vulnerability databases

---

## Learning Outcomes

Building this project demonstrates knowledge of Python socket programming, TCP/IP networking, TCP three-way handshakes, SYN/ACK/RST/ICMP responses, raw packet construction with Scapy, IPv4/IPv6 dual-stack handling, multithreading and thread pools, TLS/certificate parsing with the standard library, command-line application design and argument parsing, DNS and CIDR resolution, error handling, Python packaging (`pyproject.toml`, console entry points, `src/` layout), automated testing with `pytest` and coverage, and CI with GitHub Actions.

---

## Responsible Use

Only scan systems and networks that you own or have explicit permission to test. Examples of authorized targets include your own computer, your own router, your personal home laboratory, a university cybersecurity laboratory, a client system covered by written authorization, or a deliberately public scanning target that explicitly permits testing.

Unauthorized scanning may violate local laws, computer misuse laws, contracts, acceptable-use policies, internet service provider policies, or workplace/university security rules. The author accepts no responsibility for misuse of this software.

Use this project for education, authorized security testing, and network troubleshooting only.
