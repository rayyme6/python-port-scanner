"""portscanner.net — target parsing, DNS/CIDR resolution, address helpers.

Everything here is pure target/address bookkeeping: turning a ``-p`` spec,
a hostname, or a CIDR block into the concrete IPv4/IPv6 endpoints the scan
engines actually probe. Nothing in this module sends a packet.
"""

import ipaddress
import socket

DEFAULT_MAX_TARGETS = 256
DEFAULT_MAX_PROBES = 1_000_000


def parse_ports(port_spec):
    """Parse values such as '22,80,443', '1-1024', or a mixture."""
    ports = set()

    for raw_part in port_spec.split(","):
        part = raw_part.strip()
        if not part:
            continue

        try:
            if "-" in part:
                if part.count("-") != 1:
                    raise ValueError
                start_text, end_text = part.split("-", 1)
                start = int(start_text)
                end = int(end_text)

                if not 1 <= start <= end <= 65535:
                    raise ValueError

                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError
                ports.add(port)
        except ValueError:
            raise ValueError("invalid port or range: '{}'".format(part))

    if not ports:
        raise ValueError("no ports specified")

    return sorted(ports)


def strip_address_brackets(value):
    """Remove URI-style brackets from an IPv6 literal."""
    value = str(value).strip()
    if value.startswith("[") and value.endswith("]"):
        return value[1:-1]
    return value


def address_family(address):
    """Return socket.AF_INET or socket.AF_INET6 for an IP literal."""
    parsed = ipaddress.ip_address(strip_address_brackets(address))
    return socket.AF_INET6 if parsed.version == 6 else socket.AF_INET


def address_family_name(address_or_family):
    """Return a stable human-readable address-family label."""
    family = (
        address_or_family
        if isinstance(address_or_family, int)
        else address_family(address_or_family)
    )
    if family == socket.AF_INET6:
        return "IPv6"
    if family == socket.AF_INET:
        return "IPv4"
    return "unknown"


def socket_endpoint(address, port):
    """Build the correct connect() endpoint for IPv4 or IPv6."""
    address = strip_address_brackets(address)
    if address_family(address) == socket.AF_INET:
        return address, int(port)

    host = address
    scope_id = 0
    if "%" in address:
        host, scope = address.rsplit("%", 1)
        try:
            scope_id = int(scope)
        except ValueError:
            try:
                scope_id = socket.if_nametoindex(scope)
            except (AttributeError, OSError):
                raise ValueError("unknown IPv6 scope interface '{}'".format(scope))
    return host, int(port), 0, scope_id


def resolve_target(target, family="auto"):
    """Resolve a hostname or IP literal to one IPv4 or IPv6 address.

    ``auto`` preserves the scanner's historical IPv4 preference when both
    families are available, while still accepting IPv6 literals and falling
    back to IPv6-only DNS results. ``ipv4`` and ``ipv6`` force one family.
    """
    if family not in {"auto", "ipv4", "ipv6"}:
        raise ValueError("unknown address family: {}".format(family))

    candidate = strip_address_brackets(target)
    try:
        literal = ipaddress.ip_address(candidate)
    except ValueError:
        literal = None

    if literal is not None:
        literal_family = "ipv6" if literal.version == 6 else "ipv4"
        if family != "auto" and family != literal_family:
            raise ValueError(
                "target '{}' is {}, but --{} was requested".format(
                    target, literal_family.upper(), "6" if family == "ipv6" else "4"
                )
            )
        return str(literal)

    requested_family = {
        "auto": socket.AF_UNSPEC,
        "ipv4": socket.AF_INET,
        "ipv6": socket.AF_INET6,
    }[family]

    try:
        records = socket.getaddrinfo(
            candidate,
            None,
            requested_family,
            socket.SOCK_STREAM,
        )
    except socket.gaierror:
        raise ValueError("could not resolve host '{}'".format(target))

    addresses = []
    for record_family, _socktype, _protocol, _canonname, sockaddr in records:
        if record_family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = sockaddr[0]
        item = (record_family, address)
        if item not in addresses:
            addresses.append(item)

    if not addresses:
        raise ValueError("could not resolve host '{}'".format(target))

    if family == "auto":
        addresses.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
    return addresses[0][1]


def chunked(values, size):
    """Yield slices of values with at most size entries each."""
    for start in range(0, len(values), size):
        yield values[start:start + size]


def read_target_file(path):
    """Read target specifications from a UTF-8 text file.

    Blank lines and lines beginning with ``#`` are ignored. Inline comments are
    supported after whitespace, so ``192.0.2.1  # router`` is valid.
    """
    specifications = []
    try:
        with open(path, "r", encoding="utf-8") as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if " #" in line:
                    line = line.split(" #", 1)[0].rstrip()
                if not line:
                    continue
                specifications.append(line)
    except OSError as exc:
        raise ValueError("could not read target file '{}': {}".format(path, exc))
    return specifications


def network_host_count(network):
    """Return the number of addresses yielded by ``network.hosts()``."""
    if network.version == 4:
        if network.prefixlen >= 31:
            return int(network.num_addresses)
        return max(0, int(network.num_addresses) - 2)
    if network.prefixlen >= 127:
        return int(network.num_addresses)
    return max(0, int(network.num_addresses) - 1)


def parse_network_spec(specification):
    """Return an ip_network object for a CIDR specification, or ``None``."""
    specification = str(specification).strip()
    if "/" not in specification:
        return None

    # Accept URI-style bracketed IPv6 CIDRs such as ``[2001:db8::]/126``.
    if specification.startswith("[") and "]" in specification:
        closing = specification.index("]")
        specification = specification[1:closing] + specification[closing + 1:]
    try:
        return ipaddress.ip_network(specification, strict=False)
    except ValueError:
        return None


def collect_targets(
    positional_targets,
    target_files=None,
    family="auto",
    max_targets=DEFAULT_MAX_TARGETS,
):
    """Expand direct targets, target files, and CIDR ranges safely.

    Targets are deduplicated by resolved address while preserving first-seen
    order. CIDR ranges use ``ipaddress.ip_network(...).hosts()`` so ordinary
    IPv4 network and broadcast addresses are not scanned.
    """
    max_targets = int(max_targets)
    if max_targets <= 0:
        raise ValueError("max targets must be greater than zero")

    specifications = [str(value).strip() for value in positional_targets or []]
    for file_path in target_files or []:
        specifications.extend(read_target_file(file_path))
    specifications = [value for value in specifications if value]
    if not specifications:
        raise ValueError("provide at least one TARGET or --targets-file FILE")

    targets = []
    seen = set()

    def add_target(input_value, resolved_ip, expanded_from=None):
        key = (address_family(resolved_ip), resolved_ip)
        if key in seen:
            return
        if len(targets) >= max_targets:
            raise ValueError(
                "target expansion exceeds --max-targets {} (increase the limit "
                "only for an authorized scan)".format(max_targets)
            )
        seen.add(key)
        targets.append({
            "input": str(input_value),
            "resolved_ip": str(resolved_ip),
            "address_family": address_family_name(resolved_ip),
            "expanded_from": expanded_from,
        })

    for specification in specifications:
        network = parse_network_spec(specification)
        if "/" in specification and network is None:
            raise ValueError("invalid CIDR target: '{}'".format(specification))
        if network is not None:
            network_family = "ipv6" if network.version == 6 else "ipv4"
            if family != "auto" and family != network_family:
                raise ValueError(
                    "target '{}' is {}, but --{} was requested".format(
                        specification,
                        network_family.upper(),
                        "6" if family == "ipv6" else "4",
                    )
                )
            remaining = max_targets - len(targets)
            count = network_host_count(network)
            overlapping = 0
            for _seen_family, seen_address in seen:
                try:
                    if ipaddress.ip_address(seen_address) in network:
                        overlapping += 1
                except ValueError:
                    continue
            new_count = max(0, count - overlapping)
            if new_count > remaining:
                raise ValueError(
                    "CIDR '{}' expands to {} host(s) ({} new), exceeding the "
                    "remaining --max-targets capacity of {}".format(
                        specification, count, new_count, remaining
                    )
                )
            for host in network.hosts():
                add_target(str(host), str(host), expanded_from=specification)
            continue

        if family == "auto":
            # Preserve compatibility with one-argument resolvers and callers.
            resolved = resolve_target(specification)
        else:
            resolved = resolve_target(specification, family=family)
        add_target(specification, resolved)

    if not targets:
        raise ValueError("no usable targets were produced")
    return targets


def validate_probe_plan(target_count, port_count, max_probes=DEFAULT_MAX_PROBES):
    """Validate and return the planned target/port probe count."""
    max_probes = int(max_probes)
    if max_probes <= 0:
        raise ValueError("max probes must be greater than zero")
    planned = int(target_count) * int(port_count)
    if planned > max_probes:
        raise ValueError(
            "scan would schedule {:,} target-port probe(s), exceeding "
            "--max-probes {:,}; narrow the targets/ports or explicitly raise "
            "the limit for an authorized scan".format(planned, max_probes)
        )
    return planned


# ---------------------------------------------------------------------------
# Service and banner identification
# ---------------------------------------------------------------------------


def is_ip_literal(value):
    """Return True when value is an IPv4 or IPv6 literal rather than a hostname."""
    try:
        ipaddress.ip_address(strip_address_brackets(value))
        return True
    except ValueError:
        return False
