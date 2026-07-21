"""portscanner.scan_result — shared result model used by both scan engines.

``make_result`` builds the small dict every scan engine and report writer
agrees on, and ``ScanInterrupted`` is the exception both engines raise so a
Ctrl+C still produces a partial, ordered report instead of losing everything.
"""

from . import __version__

SCANNER_NAME = "python-port-scanner"
SCANNER_VERSION = __version__


class ScanInterrupted(KeyboardInterrupt):
    """Carry safely collected results when a user interrupts a scan stage."""

    def __init__(
        self,
        results=None,
        stage="scan",
        stage_completed=None,
        stage_total=None,
    ):
        super().__init__()
        self.results = sorted(
            list(results or []),
            key=lambda result: int(result.get("port", 0)),
        )
        self.stage = str(stage)
        self.stage_completed = int(
            len(self.results) if stage_completed is None else stage_completed
        )
        self.stage_total = int(
            self.stage_completed if stage_total is None else stage_total
        )


# Conventional service labels. These are fallbacks, not definitive proof of
# which application is actually listening on a port.


COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    111: "RPCbind", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    631: "IPP", 636: "LDAPS", 853: "DNS-over-TLS", 989: "FTPS-DATA",
    990: "FTPS", 992: "TelnetS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2375: "Docker", 2376: "Docker-TLS",
    3000: "Dev-HTTP",
    3306: "MySQL", 3389: "RDP", 5000: "Dev-HTTP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 9443: "HTTPS-Alt",
    10443: "HTTPS-Alt", 27017: "MongoDB",
}

# Plain HTTP probes are useful on likely web ports and unknown ports. They are
# intentionally not sent to known non-HTTP protocols such as DNS or Telnet.


def make_result(port, state, reason, service=None, banner=""):
    """Create one consistently shaped result dictionary."""
    return {
        "port": port,
        "state": state,
        "service": service or (
            COMMON_PORTS.get(port, "unknown") if state == "open" else "unknown"
        ),
        "banner": banner,
        "reason": reason,
    }
