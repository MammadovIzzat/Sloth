"""Service-family colours for the console UI.

The redesign colours every open port by the kind of service behind it — web,
remote access, database, file share, infrastructure — so a host's row reads as a
shape at a glance rather than a list of numbers. Ports are classified first by a
known port number, then by a keyword in the service name masscan/nmap reported,
and otherwise fall back to a neutral family.
"""

# family key -> hue (text), bg (pill fill), label
FAMILIES = {
    "web":     {"hue": "#8ab2f5", "bg": "color-mix(in srgb,#5b8def 16%,transparent)", "label": "web"},
    "remote":  {"hue": "#f0c076", "bg": "color-mix(in srgb,#e0a03a 16%,transparent)", "label": "remote"},
    "data":    {"hue": "#cbb0f5", "bg": "color-mix(in srgb,#a67ce8 16%,transparent)", "label": "database"},
    "file":    {"hue": "#ffb4b6", "bg": "color-mix(in srgb,#f2555a 16%,transparent)", "label": "file share"},
    "infra":   {"hue": "#7fd8b0", "bg": "color-mix(in srgb,#3fb984 16%,transparent)", "label": "infra"},
    "neutral": {"hue": "rgba(233,233,237,.72)", "bg": "rgba(233,233,237,.08)", "label": "other"},
}

# Well-known ports -> family. Covers the services the design tallies plus the
# common ones a sweep turns up.
_PORTS = {
    21: "file", 20: "file", 22: "remote", 23: "remote", 25: "infra",
    53: "infra", 67: "infra", 68: "infra", 69: "file", 88: "infra",
    110: "infra", 111: "infra", 123: "infra", 135: "remote", 137: "file",
    138: "file", 139: "file", 143: "infra", 161: "infra", 162: "infra",
    389: "infra", 443: "web", 445: "file", 465: "infra", 500: "infra",
    514: "infra", 515: "file", 587: "infra", 631: "file", 636: "infra",
    993: "infra", 995: "infra", 1433: "data", 1521: "data", 2049: "file",
    3268: "infra", 3306: "data", 3389: "remote", 5060: "infra", 5432: "data",
    5900: "remote", 5901: "remote", 5985: "remote", 5986: "remote",
    6379: "data", 8080: "web", 8443: "web", 8000: "web", 8008: "web",
    9200: "data", 27017: "data", 11211: "data", 80: "web",
}

# Fallback: a keyword in the service name.
_KEYWORDS = (
    ("http", "web"), ("ssl", "web"), ("www", "web"),
    ("ssh", "remote"), ("rdp", "remote"), ("vnc", "remote"),
    ("wbt", "remote"), ("telnet", "remote"), ("winrm", "remote"),
    ("mysql", "data"), ("postgres", "data"), ("mssql", "data"),
    ("oracle", "data"), ("mongo", "data"), ("redis", "data"),
    ("sql", "data"), ("elastic", "data"),
    ("smb", "file"), ("microsoft-ds", "file"), ("netbios", "file"),
    ("ftp", "file"), ("nfs", "file"), ("cifs", "file"),
    ("dns", "infra"), ("domain", "infra"), ("ldap", "infra"),
    ("smtp", "infra"), ("imap", "infra"), ("pop3", "infra"),
    ("kerberos", "infra"), ("ntp", "infra"), ("snmp", "infra"), ("sip", "infra"),
)


def surface_summary(hosts, limit=8):
    """The attack-surface band: the most common open ports across a set of
    hosts, each as {port, proto, n (hosts), service, hue, label} for the ruled
    strip the design shows under a task/project header.
    """
    from collections import Counter
    count = Counter()
    service = {}
    for h in hosts:
        seen = set()
        for p in h["ports"]:
            key = (p["port"], p["proto"])
            if key in seen:
                continue
            seen.add(key)
            count[key] += 1
            if p.get("service"):
                service.setdefault(key, p["service"])
    cells = []
    for (port, proto), n in count.most_common(limit):
        fam = port_family(port, service.get((port, proto)))
        cells.append({
            "port": port, "proto": proto, "n": n,
            "service": service.get((port, proto)) or fam["label"],
            "hue": fam["hue"], "label": service.get((port, proto)) or fam["label"],
        })
    return cells


def port_family(port, service=None):
    """Return the family dict {hue, bg, label} for a port/service."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        p = None
    if p in _PORTS:
        return FAMILIES[_PORTS[p]]
    if service:
        s = str(service).lower()
        for kw, fam in _KEYWORDS:
            if kw in s:
                return FAMILIES[fam]
    return FAMILIES["neutral"]
