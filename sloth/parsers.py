"""Parsers for masscan and nmap output."""
import re
import xml.etree.ElementTree as ET

# masscan prints these to stdout as it finds them, which is what makes live
# streaming possible: "Discovered open port 80/tcp on 192.168.1.10"
_DISCOVERY_RE = re.compile(
    r"Discovered open port (\d+)/(tcp|udp) on ([0-9a-fA-F:.]+)")

# The status line masscan repaints on stderr:
# "rate: 0.98-kpps, 12.34% done,   0:01:23 remaining, found=7"
_PROGRESS_RE = re.compile(
    r"rate:\s*([\d.]+)-kpps,\s*([\d.]+)%\s*done(?:,\s*([\d:]+)\s*remaining)?"
    r"(?:,\s*found=(\d+))?")


def parse_discovery_line(line):
    """Returns {'ip','port','proto','state'} for a masscan discovery line, else None."""
    m = _DISCOVERY_RE.search(line)
    if not m:
        return None
    port, proto, ip = m.groups()
    return {"ip": ip, "port": int(port), "proto": proto, "state": "open"}


def parse_progress_line(line):
    """Returns {'rate_kpps','percent','remaining','found'} or None."""
    m = _PROGRESS_RE.search(line)
    if not m:
        return None
    rate, percent, remaining, found = m.groups()
    return {
        "rate_kpps": float(rate),
        "percent": float(percent),
        "remaining": remaining,
        "found": int(found) if found else None,
    }


# nmap --stats-every prints: "SYN Stealth Scan Timing: About 45.30% done; ..."
_NMAP_PROGRESS_RE = re.compile(r"About\s+([\d.]+)%\s+done")


def parse_nmap_progress(line):
    """Percentage from an nmap timing line, or None."""
    m = _NMAP_PROGRESS_RE.search(line or "")
    return float(m.group(1)) if m else None


def parse_masscan_stdout(text):
    """Batch version of parse_discovery_line, kept for one-shot rescans."""
    ports = []
    for line in (text or "").splitlines():
        hit = parse_discovery_line(line)
        if hit:
            ports.append(hit)
    return ports


# rustscan --greppable prints one line per host: "192.168.1.5 -> [22,80,443]"
_RUSTSCAN_RE = re.compile(r"^\s*([0-9a-fA-F:.]+)\s*->\s*\[([0-9,\s]*)\]")


def parse_rustscan_line(line):
    """Returns (ip, [ports]) from a rustscan greppable line, or None."""
    m = _RUSTSCAN_RE.match(line or "")
    if not m:
        return None
    ip, body = m.groups()
    ports = [int(p) for p in body.replace(" ", "").split(",") if p.strip().isdigit()]
    return ip, ports


def parse_masscan_list_file(path):
    """Reads masscan's -oL output: 'open tcp 80 192.168.1.1 1730000000'.

    Written alongside the live stdout stream as the authoritative record, so a
    scan is never lost to stdout buffering.
    """
    results = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 4 or parts[0] != "open":
                    continue
                proto, port, ip = parts[1], parts[2], parts[3]
                if not port.isdigit():
                    continue
                results.append({"ip": ip, "port": int(port), "proto": proto,
                                "state": "open"})
    except OSError:
        return []
    return results


def parse_nmap_xml(xml_text):
    """Extracts per-host ports and service labels from nmap's XML output."""
    hosts = {}
    if not xml_text or not xml_text.strip():
        return hosts
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError:
        return hosts

    for host_elem in root.findall(".//host"):
        addr = None
        for a in host_elem.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        if not addr:
            continue
        ports = []
        for port_elem in host_elem.findall(".//port"):
            state_elem = port_elem.find("state")
            port_id = port_elem.get("portid")
            if state_elem is None or port_id is None:
                continue
            state = state_elem.get("state") or ""
            # UDP is often "open|filtered"; keep those plus plain "filtered".
            if not (state.startswith("open") or state == "filtered"):
                continue
            ports.append({
                "port": int(port_id),
                "proto": port_elem.get("protocol"),
                "state": state,
                "service": _service_label(port_elem.find("service")),
            })
        hosts[addr] = ports
    return hosts


def _service_label(svc_elem):
    """Builds "http" or "http (Apache httpd 2.4.58)" from an nmap <service> node."""
    if svc_elem is None:
        return None
    name = svc_elem.get("name")
    if not name:
        return None
    detail = " ".join(x for x in (svc_elem.get("product"), svc_elem.get("version")) if x)
    return f"{name} ({detail})" if detail else name
