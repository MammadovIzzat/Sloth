"""Scan type/engine definitions and form parsing.

Shared by task creation and by re-running an existing task with different
settings, so "nmap top ports now, full masscan sweep afterwards" is one task
accumulating results rather than two tasks with the findings split between them.
"""
from .config import (DEFAULT_DISCOVERY, DEFAULT_ENGINE, DEFAULT_RATE,
                     DEFAULT_RETRIES, DEFAULT_TCP_PORTS, DEFAULT_TOP_PORTS)
from .discovery import check_host_cap, get_profile
from .engine import ScanError, validate_port_spec
from .netutil import count_targets

SCAN_TYPES = {
    "full": "Full port scan",
    "quick": "Quick scan (nmap top ports)",
    "discovery": "Host discovery only",
}

# Engines for a full port scan. masscan is the fastest but runs its own TCP/IP
# stack, so it cannot cross an IPsec or VPN tunnel — the others use ordinary
# kernel sockets and can.
ENGINES = {
    "masscan": {
        "label": "masscan — fastest, huge ranges",
        "note": "Its own TCP/IP stack, so it is by far the fastest over large "
                "ranges. Cannot traverse IPsec/VPN tunnels, needs root, and "
                "under-reports when probes are dropped.",
    },
    "rustscan": {
        "label": "rustscan — fast, works through tunnels",
        "note": "Kernel TCP connect scan: works over IPsec, WireGuard and any "
                "other tunnel, and needs no root. TCP only.",
    },
    "nmap": {
        "label": "nmap — slowest, most accurate",
        "note": "Retransmits and fingerprints services, so results are the most "
                "trustworthy. Works through tunnels. Slow over large ranges.",
    },
}


def parse_scan_config(form, target, defaults=None):
    """Validates scan settings from a form into columns ready for the tasks table.

    `target` is needed to sanity-check the discovery method against the range
    size. `defaults` supplies fallbacks when re-running an existing task, so a
    field the user left alone keeps its previous value.
    """
    defaults = defaults or {}

    def pick(key, fallback):
        """Absent means "unchanged"; present-but-empty means "none".

        The distinction matters: clearing the TCP field is how you ask for a
        UDP-only scan, so an empty string must not be quietly refilled with the
        default range.
        """
        value = form.get(key)
        return fallback if value is None else value

    def pick_value(key, fallback):
        """For fields that must always hold something — selects and numbers."""
        value = form.get(key)
        if value is None or str(value).strip() == "":
            return fallback
        return value

    scan_type = str(pick_value("scan_type",
                               defaults.get("scan_type") or "full")).strip()
    if scan_type not in SCAN_TYPES:
        raise ScanError(f"Unknown scan type: {scan_type!r}")

    method = form.get("discovery")
    if method is None:
        method = defaults.get("discovery")
    method = (method or "").strip() or None
    if method and get_profile(method) is None:
        raise ScanError(f"Unknown discovery method: {method!r}")
    if scan_type == "discovery" and not method:
        method = DEFAULT_DISCOVERY
    if method:
        # Catch "hping3 over a /16" here rather than after the user hits Run.
        too_big = check_host_cap(get_profile(method), target, count_targets(target))
        if too_big:
            raise ScanError(too_big)

    engine = str(pick_value("engine",
                            defaults.get("engine") or DEFAULT_ENGINE)).strip()
    tcp = udp = top = None

    if scan_type == "full":
        if engine not in ENGINES:
            raise ScanError(f"Unknown scan engine: {engine!r}")
        tcp = validate_port_spec(str(pick("tcp_ports", DEFAULT_TCP_PORTS)))
        udp = validate_port_spec(str(pick("udp_ports", "") or ""))
        if not tcp and not udp:
            raise ScanError("Select a TCP range, a UDP range, or both.")
        if engine == "rustscan" and not tcp:
            raise ScanError("rustscan is TCP-only — give it a TCP range.")
    elif scan_type == "quick":
        # An explicit range beats top-ports — this is how you get an accurate
        # nmap -p- when a stateless sweep under-reports.
        tcp = validate_port_spec(str(form.get("nmap_ports") or "") or "")
        if not tcp:
            top = _clamp_int(pick_value("top_ports", DEFAULT_TOP_PORTS),
                             DEFAULT_TOP_PORTS, 1, 65535)

    return {
        "scan_type": scan_type,
        "engine": engine,
        "discovery": method,
        "tcp_ports": tcp,
        "udp_ports": udp,
        "top_ports": top,
        "rate": _clamp_int(pick_value("rate", defaults.get("rate") or DEFAULT_RATE),
                           DEFAULT_RATE, 100, 10_000_000),
        "retries": _clamp_int(
            pick_value("retries", defaults.get("retries") if defaults.get("retries")
                       is not None else DEFAULT_RETRIES),
            DEFAULT_RETRIES, 0, 10),
    }


def describe(config):
    """Short human label for a run, e.g. 'full port scan · rustscan · TCP 1-65535'."""
    bits = [SCAN_TYPES.get(config["scan_type"], config["scan_type"])]
    if config["scan_type"] == "full":
        bits.append(config["engine"])
    if config.get("discovery"):
        bits.append(f"discovery: {config['discovery']}")
    if config.get("tcp_ports"):
        bits.append(f"TCP {config['tcp_ports']}")
    if config.get("udp_ports"):
        bits.append(f"UDP {config['udp_ports']}")
    if config.get("top_ports"):
        bits.append(f"top {config['top_ports']}")
    return " · ".join(bits)


def _clamp_int(value, fallback, low, high):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = fallback
    return max(low, min(number, high))
