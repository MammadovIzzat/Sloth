"""Target parsing/validation and the connectivity watchdog."""
import ipaddress
import socket
import subprocess

# Anything we hand to masscan is validated against these forms first. We always
# invoke masscan with an argument list (never a shell), but a strict whitelist
# still keeps typos and pasted junk from turning into a surprising scan.
_MAX_TARGETS = 64


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _parse_one(part):
    """Returns a canonical target string for a single IP / CIDR / a.b.c.d-e.f.g.h."""
    part = part.strip()
    if not part:
        raise ValueError("empty target")

    if "-" in part:
        lo, _, hi = part.partition("-")
        lo, hi = lo.strip(), hi.strip()
        # masscan also accepts a short form like 10.0.0.1-50
        if "." not in hi and hi.isdigit():
            octets = lo.split(".")
            if len(octets) != 4:
                raise ValueError(f"invalid range: {part}")
            hi = ".".join(octets[:3] + [hi])
        first, last = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
        if first.version != last.version:
            raise ValueError(f"mixed address families in range: {part}")
        if int(last) < int(first):
            raise ValueError(f"range end is before its start: {part}")
        return f"{first}-{last}"

    if "/" in part:
        net = ipaddress.ip_network(part, strict=False)
        return str(net)

    return str(ipaddress.ip_address(part))


def normalize_target(raw):
    """Validates a comma-separated target spec and returns the cleaned string.

    Accepts single addresses, CIDRs and ranges, IPv4 or IPv6. Raises ValueError
    with a message suitable for showing to the user.
    """
    if not raw or not raw.strip():
        raise ValueError("No target given.")
    parts = [p for p in raw.replace(" ", ",").split(",") if p.strip()]
    if len(parts) > _MAX_TARGETS:
        raise ValueError(f"Too many targets ({len(parts)}); {_MAX_TARGETS} is the limit.")
    return ",".join(_parse_one(p) for p in parts)


def apply_start_ip(target, start_octet):
    """Narrows a single IPv4 CIDR to start at the given last octet.

    Under the old per-host scanner this was a filter over the expanded host list.
    Now that the whole range goes to masscan in one process, it becomes a range.
    Anything it can't express (multiple targets, IPv6) is returned untouched.
    """
    if not start_octet:
        return target
    try:
        start = int(start_octet)
    except (TypeError, ValueError):
        return target
    if "," in target or "/" not in target:
        return target
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return target
    if net.version != 4 or net.prefixlen < 24:
        return target

    hosts = list(net.hosts())
    if not hosts:
        return target
    kept = [h for h in hosts if int(str(h).split(".")[-1]) >= start]
    if not kept:
        raise ValueError(f"Start IP .{start} excludes every host in {target}.")
    return f"{kept[0]}-{kept[-1]}"


def count_targets(target):
    """Rough host count for display. Returns None when it can't tell."""
    total = 0
    for part in target.split(","):
        try:
            if "-" in part:
                lo, _, hi = part.partition("-")
                total += int(ipaddress.ip_address(hi)) - int(ipaddress.ip_address(lo)) + 1
            elif "/" in part:
                total += ipaddress.ip_network(part, strict=False).num_addresses
            else:
                ipaddress.ip_address(part)
                total += 1
        except ValueError:
            return None
    return total


def is_loopback_target(target):
    """True when every part of a target spec is loopback.

    masscan drives its own userland TCP/IP stack and transmits through a network
    adapter, so packets to 127.0.0.0/8 never reach it — a loopback scan always
    reports nothing, however many ports are actually listening. Worth saying out
    loud rather than letting someone burn a full-port sweep on it.
    """
    parts = [p for p in (target or "").split(",") if p.strip()]
    if not parts:
        return False
    for part in parts:
        try:
            if "-" in part:
                lo, _, hi = part.partition("-")
                if not (ipaddress.ip_address(lo).is_loopback
                        and ipaddress.ip_address(hi).is_loopback):
                    return False
            elif "/" in part:
                if not ipaddress.ip_network(part, strict=False).is_loopback:
                    return False
            elif not ipaddress.ip_address(part).is_loopback:
                return False
        except ValueError:
            return False
    return True


def check_internet(timeout=2.0):
    """DNS round-trip against a well-known name.

    Uses a per-socket timeout instead of socket.setdefaulttimeout(), which the
    previous version left set globally for the whole process, and catches OSError
    so a timeout doesn't propagate out of the watchdog.
    """
    try:
        socket.getaddrinfo("google.com", 80, proto=socket.IPPROTO_TCP)
        return True
    except OSError:
        pass
    # DNS may be broken while routing is fine; fall back to a raw TCP connect.
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=timeout):
            return True
    except OSError:
        return False


def route_for(ip):
    """Asks the kernel how it would reach an address.

    Returns {'dev','src','via','table'} or None. Used to detect the case where
    masscan simply cannot work, which is otherwise invisible: it looks like a
    quiet host rather than a scanner that never delivered a packet.
    """
    try:
        out = subprocess.run(["ip", "route", "get", ip], capture_output=True,
                             text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    if not out.strip():
        return None
    tokens = out.split()
    info = {"dev": None, "src": None, "via": None, "table": None}
    for key in ("dev", "src", "via", "table"):
        if key in tokens:
            idx = tokens.index(key)
            if idx + 1 < len(tokens):
                info[key] = tokens[idx + 1]
    return info


def _addresses_on(dev):
    try:
        out = subprocess.run(["ip", "-o", "addr", "show", "dev", dev],
                             capture_output=True, text=True, timeout=5,
                             check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    found = set()
    for line in out.splitlines():
        parts = line.split()
        if "inet" in parts or "inet6" in parts:
            for i, tok in enumerate(parts):
                if tok in ("inet", "inet6") and i + 1 < len(parts):
                    found.add(parts[i + 1].split("/")[0])
    return found


# Interface name prefixes that carry traffic the kernel encapsulates.
_TUNNEL_DEVS = ("tun", "tap", "wg", "ppp", "ipsec", "utun", "gre", "sit", "vti")


def ipsec_out_networks():
    """Destination networks covered by an outbound IPsec policy.

    Reading these needs root, which the tool has anyway. A policy routing table
    on its own is not enough to conclude anything — a strongSwan install puts
    every route in table 220 while only encrypting the protected subnets, so the
    xfrm policy is the signal that actually distinguishes them.
    """
    try:
        out = subprocess.run(["ip", "xfrm", "policy"], capture_output=True,
                             text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or "Operation not permitted" in (out.stderr or ""):
        return None      # cannot tell; callers must not assume anything

    networks, pending = [], None
    for line in out.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("src ") and " dst " in stripped:
            parts = stripped.split()
            pending = parts[parts.index("dst") + 1]
        elif stripped.startswith("dir out") and pending:
            try:
                networks.append(ipaddress.ip_network(pending, strict=False))
            except ValueError:
                pass
            pending = None
    return networks


def masscan_reachability(ip, ipsec_networks=None):
    """Whether masscan can plausibly deliver packets to this address.

    masscan brings its own TCP/IP stack and writes raw frames straight to a
    network adapter, so anything the *kernel* would do on the way out — IPsec
    transforms, tunnel encapsulation, policy routing to a different source
    address — simply does not happen. Packets leave in the clear, from the wrong
    address, and never arrive. The scan then reports an empty host, which is
    indistinguishable from a genuinely quiet one.

    Returns (ok, reason).
    """
    route = route_for(ip)
    if not route or not route.get("dev"):
        return True, None
    dev = route["dev"]

    if dev.startswith(_TUNNEL_DEVS):
        return False, (
            f"the route to {ip} goes over {dev}, a tunnel interface. masscan "
            f"bypasses the kernel and cannot encapsulate traffic, so its packets "
            f"will not traverse it. Use the nmap or rustscan engine instead.")

    networks = ipsec_out_networks() if ipsec_networks is None else ipsec_networks
    if networks:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None:
            for net in networks:
                if addr.version == net.version and addr in net:
                    return False, (
                        f"{ip} falls inside {net}, which the kernel protects with "
                        f"an IPsec policy. masscan writes raw frames straight to "
                        f"{dev} and never applies that transform, so its packets "
                        f"leave unencrypted and are dropped — the scan will look "
                        f"like a quiet host. Use the nmap or rustscan engine.")

    src = route.get("src")
    if src and src not in _addresses_on(dev):
        return False, (
            f"the kernel would send from {src}, which is not an address "
            f"configured on {dev}. masscan sources from the adapter's own "
            f"address, so replies will not come back.")

    return True, None


def web_url_for(ip, port_dict, web_ports):
    """Builds an http(s) URL if this port looks like a web app, else None."""
    if port_dict.get("proto") != "tcp":
        return None
    name = (port_dict.get("service") or "").lower()
    try:
        port = int(port_dict["port"])
    except (KeyError, TypeError, ValueError):
        return None
    if "http" not in name and port not in web_ports:
        return None
    https = ("https" in name) or ("ssl" in name) or port in (443, 8443)
    scheme = "https" if https else "http"
    host = f"[{ip}]" if ":" in ip else ip
    return f"{scheme}://{host}:{port}"
