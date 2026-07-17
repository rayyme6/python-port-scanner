# Python Port Scanner

A command-line TCP port scanner written in Python for learning network programming, conducting authorized security assessments, and troubleshooting network services.

The scanner supports a multithreaded TCP connect mode and a packet-level half-open SYN mode using Scapy. It can scan custom port ranges, perform basic service and banner identification, display scan progress, and export results to a text file.

> **Responsible use:** Only scan systems and networks that you own or have explicit permission to test.

---

## Features

* Multithreaded TCP connect scanning
* Half-open TCP SYN scanning with Scapy
* Hostname and IPv4 address support
* Individual ports, port ranges, and mixed port specifications
* Basic service identification
* Banner grabbing
* HTTP service probing
* Configurable timeouts
* Configurable thread counts for connect scans
* Live progress display
* Plain-text report export
* Detection of completely silent or unreachable targets
* Graceful error handling
* No external dependency required for TCP connect scans

---

## Scan Modes

| Mode             | Flag    | Library         | Privileges           | Description                                                                                                                                                                                    |
| ---------------- | ------- | --------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP Connect scan | Default | Python `socket` | None                 | Completes the full TCP three-way handshake. It is multithreaded, reliable, and works without administrative privileges.                                                                        |
| SYN scan         | `--syn` | Scapy           | Root / Administrator | Sends TCP SYN packets and examines the replies without completing the handshake. The current implementation scans ports sequentially and may be slower than the multithreaded connect scanner. |

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

The SYN scanner uses Scapy to create and send raw TCP packets.

Typical responses are interpreted as follows:

```text
SYN-ACK response  → Open
RST response      → Closed
No response       → Filtered, dropped, or unreachable
ICMP response     → Network device or firewall responded
```

When a port returns a SYN-ACK, the scanner immediately sends a TCP reset packet:

```text
Scanner → SYN
Target  → SYN-ACK
Scanner → RST
```

This prevents the normal TCP handshake from being completed.

> **Note:** Port discovery in SYN mode is half-open, but banner identification creates a normal TCP connection to each discovered open port. Use `--syn --no-banner` when you only want half-open port discovery.

---

## Requirements

* Python 3.8 or newer
* Linux or macOS for SYN scanning
* Scapy for SYN scanning
* Root privileges for raw SYN packets

The standard TCP connect scanner only uses Python's standard library.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/python-port-scanner.git
cd python-port-scanner
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install the project requirements:

```bash
pip install -r requirements.txt
```

The `requirements.txt` file installs Scapy, which is required only for SYN scanning.

---

## Usage

Basic syntax:

```bash
python3 port_scanner.py TARGET [OPTIONS]
```

Display the complete help menu:

```bash
python3 port_scanner.py --help
```

---

## Examples

### Scan TCP ports 1 through 1024

```bash
python3 port_scanner.py 192.168.1.10
```

The default port range is `1-1024`.

This means the scanner checks every TCP port from 1 through 1024. It does not use Nmap's list of the 1,024 most common ports.

### Scan specific ports

```bash
python3 port_scanner.py 192.168.1.10 -p 22,80,443
```

### Scan a port range

```bash
python3 port_scanner.py 192.168.1.10 -p 1-5000
```

### Scan a mixture of ports and ranges

```bash
python3 port_scanner.py 192.168.1.10 -p 22,80,443,8000-8100
```

### Scan a hostname

```bash
python3 port_scanner.py example.com -p 80,443
```

### Change the timeout

```bash
python3 port_scanner.py 192.168.1.10 -p 1-1024 --timeout 0.5
```

A shorter timeout makes scanning faster but may miss slow responses.

A longer timeout is more reliable on slow networks but may significantly increase scan duration.

### Change the number of threads

```bash
python3 port_scanner.py 192.168.1.10 -p 1-5000 --threads 100
```

The thread setting applies only to TCP connect scans.

### Perform a SYN scan

When using the virtual environment:

```bash
sudo .venv/bin/python port_scanner.py 192.168.1.10 -p 1-1024 --syn
```

Raw packet creation normally requires root privileges.

### Perform a SYN scan without banner grabbing

```bash
sudo .venv/bin/python port_scanner.py 192.168.1.10 -p 1-1024 --syn --no-banner
```

This performs half-open port discovery without making additional full TCP connections for service identification.

### Skip banner grabbing in connect mode

```bash
python3 port_scanner.py 192.168.1.10 -p 1-65535 --no-banner
```

This can make the scan faster when only open port numbers are required.

### Save the report to a file

```bash
python3 port_scanner.py 192.168.1.10 -p 1-1024 -o report.txt
```

The output file includes:

* Target hostname or IP address
* Resolved IP address
* Scan type
* Date and time
* Scan duration
* Open ports
* Service labels
* Captured banners

---

## Command-Line Options

| Argument          | Purpose                                                    |
| ----------------- | ---------------------------------------------------------- |
| `target`          | Target IPv4 address or hostname                            |
| `-p`, `--ports`   | Ports to scan, such as `22,80,443`, `1-1024`, or a mixture |
| `-t`, `--timeout` | Per-port timeout in seconds                                |
| `--threads`       | Maximum number of concurrent threads for TCP connect scans |
| `--syn`           | Use the Scapy SYN scanner                                  |
| `--no-banner`     | Skip service and banner identification                     |
| `-o`, `--output`  | Write the scan report to a text file                       |
| `-h`, `--help`    | Display the help menu                                      |

Default values:

```text
Ports:   1-1024
Timeout: 1.0 second
Threads: 200
Mode:    TCP connect scan
```

---

## Example Output

```text
Target: 192.168.100.1 (192.168.100.1)
Ports : 1024
Mode  : TCP connect scan (socket)

  scanned 1024/1024 ports.

==============================================================
  Scan report for 192.168.100.1 (192.168.100.1)
  Scan type : TCP connect scan (socket)
  Duration  : 5.44s
==============================================================

  PORT    STATE   SERVICE         BANNER
  ------  -----   -------         ------------------------------
  23      open    Telnet
  53      open    DNS
  80      open    HTTP            HTTP/1.1 404 Not Found

  3 open port(s) found.
```

In this example:

* TCP port 23 accepted a connection.
* TCP port 53 accepted a connection.
* TCP port 80 accepted a connection and returned an HTTP response.
* The service names for ports without banners may be based on their conventional port assignments.

---

## How It Works

The program follows this general process:

```text
Read command-line arguments
        ↓
Resolve the target to an IPv4 address
        ↓
Parse and validate the port specification
        ↓
Select TCP connect or SYN scanning
        ↓
Probe every requested port
        ↓
Collect open ports
        ↓
Attempt service and banner identification
        ↓
Print the results
        ↓
Optionally save a report
```

---

## Port Parsing

The scanner accepts several port formats.

### Single port

```text
80
```

### Multiple ports

```text
22,80,443
```

### Port range

```text
1-1024
```

### Mixed input

```text
22,80,443,8000-8100
```

Duplicate ports are automatically removed, and the final list is sorted.

Valid port numbers range from 1 through 65535.

Invalid examples include:

```text
0
65536
100-50
abc
```

---

## TCP Connect Scanning

The TCP connect scanner uses `socket.connect_ex()` to test each port.

Possible outcomes include:

### Open

The connection succeeds and `connect_ex()` returns `0`.

```text
is_open = True
got_reply = True
```

### Closed

The target actively refuses the connection.

```text
is_open = False
got_reply = True
```

This usually means the host is reachable, but no application is listening on that port.

### No useful response

The connection attempt times out or is silently dropped.

```text
is_open = False
got_reply = False
```

Possible causes include:

* A firewall silently dropped the probe
* The host is offline
* The target address is incorrect
* A routing problem exists
* The timeout is too short
* Packet loss occurred

The connect scanner uses a thread pool so that many ports can be tested concurrently.

---

## SYN Scanning

The SYN scanner uses Scapy to create a packet containing an IP layer and a TCP layer:

```python
IP(dst=target_ip) / TCP(
    sport=source_port,
    dport=destination_port,
    flags="S"
)
```

The packet contains:

* Target IPv4 address
* Random high-numbered source port
* Destination port being tested
* SYN flag
* Random TCP sequence number

Scapy sends the packet and waits for a response.

### SYN-ACK response

A SYN-ACK normally indicates that the port is open.

The scanner sends a reset packet to terminate the half-open connection.

### RST response

A reset normally indicates that the port is closed.

### No response

A missing response can indicate filtering, packet loss, an unreachable target, or a host that is offline.

### ICMP response

An ICMP error may be returned by a router, firewall, or the target system.

The current SYN scanner tests one port at a time. Future versions may use Scapy's batched sending functions for improved performance.

---

## Service and Banner Identification

After an open port is discovered, the scanner attempts basic service identification.

The process is:

1. Assign a fallback service name based on the conventional port number.
2. Open a TCP connection to the port.
3. Wait briefly for the service to send a banner.
4. If nothing is received, send a generic HTTP `HEAD` request.
5. Examine the response for recognizable protocols.

Some services immediately send identifying banners.

Example SSH banner:

```text
SSH-2.0-OpenSSH_9.6
```

Example FTP banner:

```text
220 FTP Server Ready
```

Example SMTP banner:

```text
220 mail.example.com ESMTP
```

For silent services, the scanner sends:

```http
HEAD / HTTP/1.0
Host: TARGET_IP
```

If the response begins with `HTTP/`, the service is identified as HTTP.

Example:

```text
HTTP/1.1 404 Not Found
```

A `404 Not Found` response is still evidence that an HTTP server accepted and processed the request. It does not indicate that the port is closed.

---

## Service-Identification Accuracy

Service names based only on port numbers are best-effort labels, not definitive identification.

For example, an open TCP port 23 is labelled `Telnet` because port 23 is conventionally associated with Telnet. However, another application could be configured to listen on that port.

The scanner provides stronger identification when it receives:

* A recognizable banner
* An SSH protocol string
* A valid HTTP response
* An HTTP `Server` header

The scanner does not perform full service-version fingerprinting like:

```bash
nmap -sV
```

---

## Understanding Port States

### Open

A program is accepting TCP connections on the port.

### Closed

The host responded, but no program is accepting connections on the port.

### Filtered

A firewall or network device may be blocking or silently dropping the probe.

### Unreachable or unresponsive

The target may be offline, incorrectly addressed, separated by a routing problem, or protected by filtering.

The current final report lists open ports only.

---

## Completely Silent Targets

Both scanning engines track whether the target returned any response.

An open-port response and an explicit rejection both confirm that something responded.

If every probe times out with no replies, the scanner prints a warning instead of confidently reporting that the host has no open ports.

A completely silent result may mean:

* The target is offline
* The target changed IP address
* A firewall is silently dropping packets
* Wireless client isolation is enabled
* The devices are on different VLANs
* Routing between the scanner and target is unavailable
* The timeout is too short

Useful troubleshooting commands include:

```bash
ping -c 4 192.168.1.10
```

```bash
ip route
```

```bash
ip neigh
```

You can also check your router's DHCP client or connected-device list.

---

## Virtual Environment and `sudo`

Installing Scapy inside a virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Running this command:

```bash
sudo python3 port_scanner.py TARGET --syn
```

may use the root user's Python environment instead of your virtual environment. Root may therefore be unable to find Scapy.

Use the Python executable inside the virtual environment:

```bash
sudo .venv/bin/python port_scanner.py TARGET --syn
```

This gives the script raw-socket privileges while still using the packages installed in `.venv`.

Avoid installing packages globally with commands such as:

```bash
sudo pip install scapy
```

because this can interfere with the operating system's managed Python environment.

---

## Project Structure

```text
python-port-scanner/
├── port_scanner.py
├── requirements.txt
└── README.md
```

### `port_scanner.py`

Contains:

* Command-line interface
* Port parsing
* Hostname resolution
* TCP connect scanner
* SYN scanner
* Banner identification
* Result formatting
* Text report generation

### `requirements.txt`

Contains the Scapy dependency required for SYN scanning.

### `README.md`

Contains installation instructions, usage examples, technical explanations, limitations, and responsible-use guidance.

---

## Real-World Applications

This project can be used in authorized environments for:

* Network troubleshooting
* Verifying whether services are reachable
* Checking server exposure
* Testing firewall configurations
* Auditing home networks
* Validating cloud server security groups
* Post-deployment service verification
* Cybersecurity laboratory exercises
* Learning socket programming
* Learning TCP packet structure
* Understanding TCP handshakes
* Basic asset and service discovery
* Defensive security assessments

It is a learning and auditing tool, not an exploitation framework.

---

## Limitations

Current limitations include:

* TCP scanning only
* No UDP scanning
* IPv4 only
* No operating-system fingerprinting
* No vulnerability detection
* No exploitation functionality
* Basic banner-based service identification
* No full service-version fingerprinting
* SYN probes are currently sent sequentially
* Final reports list only open ports
* No JSON or CSV output
* No multiple-host or subnet scanning
* No historical comparison between scan results
* Generic HTTP probes are sent to silent open services
* Banner-grabbing errors are intentionally suppressed

---

## Possible Future Improvements

Potential improvements include:

* Concurrent or batched SYN scanning
* UDP scanning
* IPv6 support
* Multiple-host scanning
* CIDR subnet support
* Closed and filtered port reporting
* Protocol-specific service probes
* Service-version fingerprinting
* JSON report export
* CSV report export
* Structured logging
* Configurable retries
* Rate limiting
* Previous-scan comparison
* Automated tests
* Better exception logging
* Optional colored terminal output
* Operating-system fingerprinting
* Integration with vulnerability databases

---

## Learning Outcomes

Building this project demonstrates knowledge of:

* Python socket programming
* TCP/IP networking
* TCP three-way handshakes
* SYN, ACK, RST, and ICMP responses
* Raw packet construction
* Scapy
* Multithreading
* Thread pools
* Timeouts
* Command-line application design
* Argument parsing
* DNS resolution
* Error handling
* Banner grabbing
* Service identification
* Report generation
* Defensive network reconnaissance

---

## Responsible Use

Only scan systems and networks that you own or have explicit permission to test.

Examples of authorized targets include:

* Your own computer
* Your own router
* Your personal home laboratory
* A university cybersecurity laboratory
* A client system covered by written authorization
* A deliberately public scanning target that explicitly permits testing

Unauthorized scanning may violate:

* Local laws
* Computer misuse laws
* Contracts
* Acceptable-use policies
* Internet service provider policies
* Workplace or university security rules

The author accepts no responsibility for misuse of this software.

Use this project for education, authorized security testing, and network troubleshooting only.

