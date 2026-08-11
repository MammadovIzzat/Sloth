"""Host discovery: find which addresses are alive before port-scanning them.

Sweeping every port of a /24 means 254 full-port scans, most of them against
nothing. Discovering live hosts first cuts the port scan down to the addresses
that actually answer — far less traffic, far less noise, and much faster.

Each method is a named profile so you can pick the probe that suits the network:
ICMP echo is the obvious one, but plenty of hosts drop it while still answering
a timestamp request, a TCP ACK to 443, or an ARP who-has on the local segment.
"""
import ipaddress
import os
import re
import subprocess
import xml.etree.ElementTree as ET

from .config import DEFAULT_RATE

# Ports worth knocking on for TCP/UDP ping probes: common enough to be open or
# at least to elicit a RST, which is all a discovery probe needs.
_SYN_PORTS = "21,22,23,25,53,80,110,143,443,445,993,995,3389,8080"
_ACK_PORTS = "80,443,3389"
_UDP_PORTS = "53,67,123,137,161"


class DiscoveryProfile:
    def __init__(self, key, label, tool, description, nmap_args=(),
                 fping_args=(), hping_args=(), local_only=False,
                 per_host=False, max_hosts=None):
        self.key = key
        self.label = label
        self.tool = tool
        self.description = description
        self.nmap_args = tuple(nmap_args)
        self.fping_args = tuple(fping_args)
        self.hping_args = tuple(hping_args)
        self.local_only = local_only      # ARP: same broadcast domain only
        self.per_host = per_host          # tool probes one address at a time
        self.max_hosts = max_hosts

    def as_dict(self):
        return {"key": self.key, "label": self.label, "tool": self.tool,
                "description": self.description, "local_only": self.local_only,
                "per_host": self.per_host, "max_hosts": self.max_hosts}


PROFILES = [
    DiscoveryProfile(
        "nmap_default", "Nmap default probes (-sn)", "nmap",
        "ICMP echo + timestamp, TCP SYN 443, TCP ACK 80, and ARP on the local "
        "segment. The balanced choice when you don't know the network.",
        nmap_args=("-sn",)),
    DiscoveryProfile(
        "nmap_icmp_echo", "ICMP echo ping (-PE)", "nmap",
        "Classic ping. Fast and quiet, but firewalls very commonly drop it.",
        nmap_args=("-sn", "-PE")),
    DiscoveryProfile(
        "nmap_icmp_timestamp", "ICMP timestamp ping (-PP)", "nmap",
        "ICMP type 13. Often answered by hosts configured to ignore echo, so "
        "worth trying when -PE finds nothing.",
        nmap_args=("-sn", "-PP")),
    DiscoveryProfile(
        "nmap_icmp_netmask", "ICMP address-mask ping (-PM)", "nmap",
        "ICMP type 17. Rarely answered by modern hosts, but free to try and "
        "occasionally finds old network gear.",
        nmap_args=("-sn", "-PM")),
    DiscoveryProfile(
        "nmap_tcp_syn", "TCP SYN ping (-PS)", "nmap",
        f"SYN to {_SYN_PORTS}. Gets through firewalls that drop ICMP; a RST "
        f"counts as alive just as much as a SYN/ACK.",
        nmap_args=("-sn", f"-PS{_SYN_PORTS}")),
    DiscoveryProfile(
        "nmap_tcp_ack", "TCP ACK ping (-PA)", "nmap",
        f"ACK to {_ACK_PORTS}. Slips past stateless filters that only block "
        f"inbound SYN.",
        nmap_args=("-sn", f"-PA{_ACK_PORTS}")),
    DiscoveryProfile(
        "nmap_udp", "UDP ping (-PU)", "nmap",
        f"UDP to {_UDP_PORTS}. A closed port replies with ICMP unreachable, "
        f"which proves the host is there.",
        nmap_args=("-sn", f"-PU{_UDP_PORTS}")),
    DiscoveryProfile(
        "nmap_sctp", "SCTP INIT ping (-PY)", "nmap",
        "SCTP INIT chunks. Niche, but telecom and some Linux hosts answer.",
        nmap_args=("-sn", "-PY")),
    DiscoveryProfile(
        "nmap_arp", "ARP ping (-PR) — local segment only", "nmap",
        "ARP who-has. Cannot be firewalled and is extremely fast and reliable, "
        "but only works on your own broadcast domain.",
        nmap_args=("-sn", "-PR"), local_only=True),
    DiscoveryProfile(
        "nmap_thorough", "Nmap thorough (every probe type)", "nmap",
        "ICMP echo/timestamp/mask plus TCP SYN, TCP ACK and UDP probes. The "
        "most likely to find hosts, and the loudest.",
        nmap_args=("-sn", "-PE", "-PP", "-PM", f"-PS{_SYN_PORTS}",
                   f"-PA{_ACK_PORTS}", f"-PU{_UDP_PORTS}")),
    DiscoveryProfile(
        "fping_sweep", "fping ICMP sweep (-a -g)", "fping",
        "Fast parallel ICMP echo sweep. Excellent for large ranges when you "
        "only care about hosts that answer ping.",
        fping_args=("-r", "1", "-t", "300")),
    DiscoveryProfile(
        "fping_thorough", "fping patient sweep (retries)", "fping",
        "Same sweep with 3 retries and a longer timeout — for lossy links or "
        "slow WAN targets where a single probe drops.",
        fping_args=("-r", "3", "-t", "1000")),
    DiscoveryProfile(
        "masscan_ping", "masscan ICMP sweep (--ping)", "masscan",
        "ICMP echo using masscan's own stack. Built for enormous ranges — a "
        "/8 is realistic. Cannot see loopback.",
        nmap_args=()),
    DiscoveryProfile(
        "hping3_icmp", "hping3 ICMP probe (per host)", "hping3",
        "One crafted ICMP echo per address. Slow — probes sequentially — so "
        "keep it to small ranges. Useful when you need control over the packet.",
        hping_args=("-1",), per_host=True, max_hosts=256),
    DiscoveryProfile(
        "hping3_syn", "hping3 TCP SYN probe (per host)", "hping3",
        "One crafted SYN to port 443 per address. Sequential and slow, but "
        "gets through ICMP-blocking filters.",
        hping_args=("-S", "-p", "443"), per_host=True, max_hosts=256),
]

PROFILES_BY_KEY = {p.key: p for p in PROFILES}


def get_profile(key):
    return PROFILES_BY_KEY.get(key)


def profiles_for_ui():
    return [p.as_dict() for p in PROFILES]


# --- target helpers ------------------------------------------------------

def check_host_cap(profile, target, count):
    """Per-host tools are far too slow for a big range — say so up front.

    Returns an explanatory message, or None when the target is within reach.
    """
    if not profile or not profile.max_hosts or not count:
        return None
    if count <= profile.max_hosts:
        return None
    return (f"{profile.label} probes one address at a time and is capped at "
            f"{profile.max_hosts}; this target has {count}. Pick an fping or "
            f"nmap sweep for a range this size.")


def expand_targets(target, limit=65536):
    """Expands a target spec into individual addresses.

    Used by the per-host tools (hping3) and to decide whether a host list needs
    to go into a file rather than onto the command line.
    """
    out = []
    for part in target.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, _, hi = part.partition("-")
                start = int(ipaddress.ip_address(lo))
                end = int(ipaddress.ip_address(hi))
                version = ipaddress.ip_address(lo).version
                for value in range(start, end + 1):
                    out.append(str(ipaddress.ip_address(value) if version == 4
                                   else ipaddress.IPv6Address(value)))
                    if len(out) > limit:
                        return out[:limit]
            elif "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                hosts = net.hosts() if net.num_addresses > 2 else net
                for addr in hosts:
                    out.append(str(addr))
                    if len(out) > limit:
                        return out[:limit]
            else:
                out.append(str(ipaddress.ip_address(part)))
        except ValueError:
            continue
    return out


def _write_target_file(path, targets):
    with open(path, "w") as fh:
        fh.write("\n".join(targets) + "\n")
    return path


# --- command building ----------------------------------------------------

def build_command(profile, target, run_dir, rate=None):
    """Returns (argv, kind) for a whole-range probe.

    `kind` tells the caller how to read the results: 'nmap_xml', 'stdout_ips'
    or 'masscan_list'.
    """
    if profile.tool == "nmap":
        cmd = ["nmap", *profile.nmap_args, "-n", "-oX", "discovery.xml"]
        cmd += _target_args(target, run_dir, "nmap")
        return cmd, "nmap_xml"

    if profile.tool == "fping":
        # -a prints only the addresses that answered; -q suppresses per-probe
        # noise. fping exits non-zero when anything is unreachable, which for a
        # sweep is the normal case, so the caller must not treat that as failure.
        cmd = ["fping", "-a", "-q", *profile.fping_args]
        expanded_file = os.path.join(run_dir, "discovery-targets.txt")
        if _is_simple_range(target):
            cmd += ["-g", *_fping_range(target)]
        else:
            _write_target_file(expanded_file, expand_targets(target))
            cmd += ["-f", os.path.basename(expanded_file)]
        return cmd, "stdout_ips"

    if profile.tool == "masscan":
        cmd = ["masscan", *target.split(","), "--ping",
               "--rate", str(rate or DEFAULT_RATE),
               "-oL", "discovery.list"]
        return cmd, "masscan_list"

    raise ValueError(f"{profile.tool} has no whole-range command form")


def build_host_command(profile, ip):
    """Per-host probe for tools that only take one address at a time."""
    if profile.tool == "hping3":
        return ["hping3", *profile.hping_args, "-c", "1", "--fast", ip]
    raise ValueError(f"{profile.tool} is not a per-host tool")


def nmap_target(part):
    """Rewrites one target into a form nmap actually accepts.

    nmap does not understand a full dotted range like 10.0.0.1-10.0.0.9 — it
    tries to resolve it as a hostname and scans nothing. It wants octet-range
    notation (10.0.0.1-9), so convert when the range sits inside one /24 and
    fall back to expanding the addresses when it doesn't.
    """
    part = part.strip()
    if "-" not in part or "/" in part:
        return [part]
    lo, _, hi = part.partition("-")
    lo, hi = lo.strip(), hi.strip()
    if "." not in hi and ":" not in hi:
        return [part]                      # already 10.0.0.1-9 form
    try:
        first, last = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
    except ValueError:
        return [part]
    if first.version == 4:
        a, b = str(first).rsplit(".", 1), str(last).rsplit(".", 1)
        if a[0] == b[0]:
            return [f"{first}-{b[1]}"]
    return expand_targets(part)


def _target_args(target, run_dir, tool):
    """Long host lists go in a file — a command line has a length limit."""
    parts = []
    for part in target.split(","):
        if part.strip():
            parts.extend(nmap_target(part))
    if len(parts) <= 64:
        return parts
    path = os.path.join(run_dir, f"{tool}-targets.txt")
    _write_target_file(path, parts)
    return ["-iL", os.path.basename(path)]


def _is_simple_range(target):
    return "," not in target and ("/" in target or "-" in target)


def _fping_range(target):
    if "/" in target:
        return [target]
    lo, _, hi = target.partition("-")
    return [lo.strip(), hi.strip()]


# --- result parsing ------------------------------------------------------

def parse_nmap_hosts(xml_text):
    """Extracts live hosts from `nmap -sn` XML output."""
    hosts = []
    if not xml_text or not xml_text.strip():
        return hosts
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError:
        return hosts

    for host_elem in root.findall(".//host"):
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = None
        for a in host_elem.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        if not addr:
            continue
        name_elem = host_elem.find("./hostnames/hostname")
        times = host_elem.find("times")
        hosts.append({
            "ip": addr,
            "state": "up",
            "reason": status.get("reason"),
            "hostname": name_elem.get("name") if name_elem is not None else None,
            "latency": times.get("srtt") if times is not None else None,
        })
    return hosts


_IP_LINE = re.compile(r"^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)\s*$")


def parse_ip_lines(text):
    """fping -a prints one live address per line."""
    hosts = []
    for line in (text or "").splitlines():
        m = _IP_LINE.match(line)
        if not m:
            continue
        try:
            ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        hosts.append({"ip": m.group(1), "state": "up", "reason": "echo-reply"})
    return hosts


_HPING_ALIVE = re.compile(r"(\d+) packets received")


def hping_is_alive(stdout, stderr):
    """hping3 reports its summary on stderr; one reply means the host answered."""
    blob = (stdout or "") + "\n" + (stderr or "")
    m = _HPING_ALIVE.search(blob)
    if m:
        return int(m.group(1)) > 0
    return "bytes from" in blob or "flags=" in blob


def parse_masscan_pings(path):
    """masscan --ping writes ICMP replies into its -oL list as proto 'icmp'."""
    hosts = []
    try:
        with open(path) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "open":
                    hosts.append({"ip": parts[3], "state": "up",
                                  "reason": "icmp-reply"})
    except OSError:
        return []
    return hosts


def run_per_host(profile, ips, spawn, log=None, should_stop=None):
    """Sequentially probes each address with a per-host tool such as hping3."""
    alive = []
    for index, ip in enumerate(ips):
        if should_stop and should_stop():
            break
        try:
            proc = spawn(build_host_command(profile, ip))
            out, err = proc.communicate(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
            except Exception:
                pass
            continue
        if hping_is_alive(out, err):
            alive.append({"ip": ip, "state": "up", "reason": profile.tool})
            if log:
                log(f"{ip} is up")
        if log and index and index % 25 == 0:
            log(f"probed {index}/{len(ips)} addresses, {len(alive)} up so far")
    return alive
