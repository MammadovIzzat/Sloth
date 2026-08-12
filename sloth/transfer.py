"""Moving whole projects between installs.

The JSON export doubles as the interchange format: one analyst exports a
project, another imports it and gets the tasks, hosts, ports, nmap output and
screenshots in their own database.

Everything arriving here was written by another machine, so none of it is
trusted. Identifiers are regenerated rather than reused, every field is
range-checked before it reaches SQL, and screenshots are verified to be PNGs
and written under names this side chose. A malformed or hostile file should
fail with a sentence, not a traceback or a stray write outside SHOTS_DIR.
"""
import base64
import binascii
import json
import os

from . import store
from .config import SHOTS_DIR
from .db import new_id, now
from .scanconfig import ENGINES, SCAN_TYPES

# Bumped when the shape changes in a way an older Sloth could not read.
FORMAT = 1

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_SHOT_BYTES = 12 * 1024 * 1024

# Statuses a task can legitimately arrive in. Anything else was still moving
# when it was exported, and there is no process on this side behind it.
TERMINAL = {"completed", "stopped", "error", "interrupted"}
STILL_RUNNING = ("This task was still running when it was exported, so its "
                 "results may be incomplete.")


class BundleError(ValueError):
    """The uploaded file is not a Sloth export, or is damaged."""


# --- writing -------------------------------------------------------------

def envelope(title, sections, project=None, version="?"):
    """The JSON export, with screenshots embedded so the file travels alone."""
    tasks = []
    for sec in sections:
        scans = {}
        for ip, scan_list in sec["scans"].items():
            scans[ip] = [dict(s, screenshots=[_pack_shot(x) for x in s["screenshots"]])
                         for s in scan_list]
        tasks.append({"task": dict(sec["task"]), "hosts": sec["hosts"], "scans": scans})

    return {
        "sloth": {"format": FORMAT, "version": version, "exported_at": now()},
        "title": title,
        "project": dict(project) if project else None,
        "tasks": tasks,
    }


def _pack_shot(shot):
    """Adds the PNG itself to a screenshot record, keeping its metadata."""
    out = dict(shot)
    out.pop("data_uri", None)          # the HTML export's field, not ours
    name = os.path.basename(out.get("file") or "")
    try:
        with open(os.path.join(SHOTS_DIR, name), "rb") as fh:
            out["data"] = base64.b64encode(fh.read()).decode()
    except OSError:
        out["data"] = None             # capture failed, or the file is long gone
    return out


# --- reading -------------------------------------------------------------

def read_bundle(raw):
    """Parses and sanity-checks an uploaded export. Raises BundleError."""
    if not raw:
        return _fail("The uploaded file is empty.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return _fail("That is not a text file. Import expects the JSON export, "
                     "not the HTML report or a zip.")
    except ValueError as exc:
        return _fail(f"The file is not valid JSON ({exc}).")

    if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
        return _fail("This does not look like a Sloth export — no task list in "
                     "it. Export with format=json, not html or txt.")

    header = data.get("sloth") or {}
    fmt = header.get("format")
    if isinstance(fmt, int) and fmt > FORMAT:
        return _fail(f"The file was written by a newer Sloth (format {fmt}, "
                     f"this one reads {FORMAT}). Upgrade before importing it.")
    return data


def _fail(message):
    raise BundleError(message)


def import_bundle(data, project_id=None):
    """Writes a parsed bundle into the database. Returns a summary dict.

    Nothing from the file names a row: project, task and scan identifiers are
    all minted here, so importing the same export twice makes two independent
    copies rather than silently overwriting the first.
    """
    target = store.get_project(project_id) if project_id else None
    if target is None:
        project_id = _new_project(data)
        created = True
    else:
        created = False

    tally = {"project": project_id, "created": created, "tasks": 0,
             "hosts": 0, "ports": 0, "scans": 0, "shots": 0, "skipped": 0}

    for entry in data["tasks"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("task"), dict):
            tally["skipped"] += 1
            continue
        _import_task(entry, project_id, tally)

    return tally


def _new_project(data):
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    name = (_text(project.get("name")) or _text(data.get("title"))
            or "Imported project")
    return store.create_project(
        _unique_name(name),
        client=_text(project.get("client")),
        description=_text(project.get("description"), 4000))


def _unique_name(name):
    """Keeps an import from being mistaken for the project it sits next to."""
    taken = {p["name"] for p in store.list_projects()}
    if name not in taken:
        return name
    for n in range(2, 100):
        candidate = f"{name} (imported {n})" if n > 2 else f"{name} (imported)"
        if candidate not in taken:
            return candidate
    return f"{name} ({new_id()})"


def _import_task(entry, project_id, tally):
    src = entry["task"]
    target = _text(src.get("target"), 500) or "(imported)"

    task_id = store.create_task(
        project_id, target,
        name=_text(src.get("name"), 300) or target,
        tcp_ports=_text(src.get("tcp_ports"), 200),
        udp_ports=_text(src.get("udp_ports"), 200),
        rate=_int(src.get("rate"), 1, 10_000_000),
        notes=_text(src.get("notes"), 4000),
        scan_type=_choice(src.get("scan_type"), SCAN_TYPES, "full"),
        discovery=_text(src.get("discovery"), 60),
        top_ports=_int(src.get("top_ports"), 1, 65535),
        retries=_int(src.get("retries"), 0, 100),
        wait=_int(src.get("wait"), 0, 3600),
        engine=_choice(src.get("engine"), ENGINES, "masscan"))
    tally["tasks"] += 1

    status = _text(src.get("status"), 40)
    error = _text(src.get("error"), 2000)
    if status not in TERMINAL:
        # Honest about what arrived: a half-finished run, not a completed one.
        status, error = "interrupted", error or STILL_RUNNING
    store.update_task(
        task_id, status=status, error=error,
        progress=_float(src.get("progress"), 0, 100) or 0,
        started_at=_text(src.get("started_at"), 40),
        finished_at=_text(src.get("finished_at"), 40),
        # There is no paused.conf on this side, so resume would only fail.
        resumable=0)

    _import_hosts(entry.get("hosts"), task_id, tally)
    _import_scans(entry.get("scans"), task_id, project_id, tally)


def _import_hosts(hosts, task_id, tally):
    if not isinstance(hosts, list):
        return
    # Grouped by discovery method so this is a couple of statements rather than
    # one round trip per host.
    by_method, findings = {}, []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        ip = _text(host.get("ip"), 60)
        if not ip:
            continue
        by_method.setdefault(_text(host.get("discovered_by"), 60), []).append({
            "ip": ip, "state": "up",
            "reason": _text(host.get("reason"), 200),
            "hostname": _text(host.get("hostname"), 300)})
        tally["hosts"] += 1

        by_source = {}
        for port in host.get("ports") or []:
            clean = _clean_port(port)
            if clean:
                by_source.setdefault(_text(port.get("source"), 40) or "masscan",
                                     []).append(clean)
        findings += [(ip, source, ports) for source, ports in by_source.items()]

    for method, group in by_method.items():
        store.add_hosts(task_id, group, method=method)
    for ip, source, ports in findings:
        tally["ports"] += len(store.add_findings(task_id, ip, ports, source=source))


def _clean_port(port):
    if not isinstance(port, dict):
        return None
    number = _int(port.get("port"), 0, 65535)
    if number is None:
        return None
    return {"port": number,
            "proto": _choice(port.get("proto"), ("tcp", "udp", "sctp"), "tcp"),
            "state": _text(port.get("state"), 40) or "open",
            "service": _text(port.get("service"), 500)}


def _import_scans(scans, task_id, project_id, tally):
    if not isinstance(scans, dict):
        return
    for ip, scan_list in scans.items():
        ip = _text(ip, 60)
        if not ip or not isinstance(scan_list, list):
            continue
        for scan in scan_list:
            if not isinstance(scan, dict):
                continue
            shots = [s for s in (_unpack_shot(x, tally)
                                 for x in scan.get("screenshots") or []) if s]
            store.save_nmap_scan(
                new_id(), ip,
                _text(scan.get("tool"), 60) or "nmap",
                _text(scan.get("command"), 4000),
                _text(scan.get("raw_output"), 2_000_000),
                [p for p in (_clean_port(x) for x in scan.get("ports") or []) if p],
                shots, task_id=task_id, project_id=project_id,
                created_at=_text(scan.get("created_at"), 40))
            tally["scans"] += 1


def _unpack_shot(shot, tally):
    """Writes an embedded screenshot out under a name chosen on this side.

    The filename in the bundle is never used — not even as a basename — so a
    crafted export cannot land a file anywhere but SHOTS_DIR, nor overwrite a
    screenshot already there.
    """
    if not isinstance(shot, dict):
        return None
    url = _text(shot.get("url"), 2000)
    blob = shot.get("data")
    if not isinstance(blob, str) or not blob:
        return {"url": url, "file": None} if url else None
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return {"url": url, "file": None} if url else None
    if not raw.startswith(PNG_MAGIC) or len(raw) > MAX_SHOT_BYTES:
        return {"url": url, "file": None} if url else None

    name = f"{new_id()}.png"
    try:
        with open(os.path.join(SHOTS_DIR, name), "wb") as fh:
            fh.write(raw)
    except OSError:
        return {"url": url, "file": None} if url else None
    tally["shots"] += 1
    return {"url": url, "file": name}


# --- field cleaning ------------------------------------------------------

def _text(value, limit=300):
    if isinstance(value, bool) or value is None:
        return None
    if not isinstance(value, (str, int, float)):
        return None
    text = str(value).strip()
    # Control characters would corrupt the text export and the log view.
    text = "".join(ch for ch in text if ch >= " " or ch in "\t\n")
    return text[:limit] or None


def _int(value, low, high):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if low <= number <= high else None


def _float(value, low, high):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return min(max(number, low), high)


def _choice(value, allowed, fallback):
    return value if isinstance(value, str) and value in allowed else fallback
