"""Scan orchestration: masscan sweeps and nmap follow-up scans.

The old engine spawned one masscan process per host with a thread pool, so a /24
meant 254 process launches and 254 rate ramp-ups. masscan is built to take the
whole range in one process, so that is what happens here: a single sweep whose
stdout is streamed line by line, giving the same live per-host UI without the
per-host overhead.

Results go to SQLite as they arrive, so a browser refresh (or a server restart)
no longer loses the scan.
"""
import errno
import os
import queue
import re
import shutil
import stat
import struct
import subprocess
import threading
import time
import uuid

CAP_NET_RAW = 13

from . import discovery, store
from .config import (DEFAULT_ENGINE, DEFAULT_RATE, DEFAULT_RETRIES,
                     DEFAULT_TCP_PORTS, DEFAULT_TOP_PORTS, MASSCAN_WAIT,
                     NMAP_TIMEOUT, RUNS_DIR, RUSTSCAN_BATCH, RUSTSCAN_TIMEOUT_MS,
                     RUSTSCAN_TRIES, RUSTSCAN_ULIMIT, STOP_GRACE_SECONDS)
from .db import now
from .netutil import (check_internet, count_targets, ipsec_out_networks,
                      is_loopback_target, masscan_reachability)
from .parsers import (parse_discovery_line, parse_masscan_list_file,
                      parse_masscan_stdout, parse_nmap_progress,
                      parse_nmap_xml, parse_progress_line, parse_rustscan_line)
from .procs import registry
from . import screenshots as shots_mod


class ScanBusy(Exception):
    """Raised when a scan is requested while another one holds the network."""


class ScanError(Exception):
    pass


class ScanCancelled(Exception):
    """Raised when the user stops a rescan mid-flight."""


def _run_dir(task_id):
    path = os.path.join(RUNS_DIR, task_id)
    os.makedirs(path, exist_ok=True)
    return path


def paused_conf_path(task_id):
    return os.path.join(_run_dir(task_id), "paused.conf")


def log_path(task_id):
    return os.path.join(_run_dir(task_id), "scan.log")


# masscan writes these keys into paused.conf but its own config parser rejects
# them on the way back in, so `--resume` dies instantly with
# "CONF: unknown config option: nocapture=servername" having scanned nothing.
# Strip them before resuming. Dropping nocapture only affects banner capture,
# which this tool never enables.
UNREADABLE_RESUME_KEYS = ("nocapture",)


def sanitize_paused_conf(path):
    """Removes keys masscan cannot read back. Returns the list of dropped lines."""
    try:
        with open(path) as fh:
            lines = fh.readlines()
    except OSError:
        return []

    dropped, kept = [], []
    for line in lines:
        flat = line.strip().lower().replace(" ", "")
        if any(flat.startswith(k + "=") for k in UNREADABLE_RESUME_KEYS):
            dropped.append(line.strip())
        else:
            kept.append(line)

    if dropped:
        try:
            with open(path, "w") as fh:
                fh.writelines(kept)
        except OSError:
            return []
    return dropped


def read_log(task_id, max_lines=400):
    """Tail of a task's scanner output, for rendering the page after a reload."""
    try:
        with open(log_path(task_id)) as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    return "".join(lines[-max_lines:])


def require_tool(name):
    path = shutil.which(name)
    if path is None:
        raise ScanError(
            f"{name} not found on PATH. Install it (e.g. 'sudo pacman -S {name}' or "
            f"'sudo apt install {name}') and run this tool as root.")
    return path


def build_port_spec(tcp_ports, udp_ports):
    """One combined -p spec so TCP and UDP go out in a single sweep."""
    parts = []
    if tcp_ports:
        parts.append(",".join(f"T:{c.strip()}" for c in tcp_ports.split(",") if c.strip()))
    if udp_ports:
        parts.append(",".join(f"U:{c.strip()}" for c in udp_ports.split(",") if c.strip()))
    spec = ",".join(p for p in parts if p)
    if not spec:
        raise ScanError("No ports selected — set a TCP range, a UDP range, or both.")
    return spec


_PORT_SPEC_RE = re.compile(r"^[0-9,\-]+$")


def validate_port_spec(value):
    """Ports arrive from a form field, so keep them to digits, commas and dashes."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if not _PORT_SPEC_RE.match(value):
        raise ScanError(f"Invalid port range: {value!r}. Use forms like 1-65535 or 22,80,443.")
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        bounds = chunk.split("-")
        if len(bounds) > 2 or not all(b.isdigit() for b in bounds):
            raise ScanError(f"Invalid port range: {chunk!r}")
        nums = [int(b) for b in bounds]
        if any(n < 1 or n > 65535 for n in nums):
            raise ScanError(f"Ports must be between 1 and 65535: {chunk!r}")
        if len(nums) == 2 and nums[1] < nums[0]:
            raise ScanError(f"Port range runs backwards: {chunk!r}")
    return value


def _check_requirements(task):
    """Verifies the tools a task needs are installed, and that we can use them.

    Which tools matter depends on the scan type, so a discovery-only or quick
    nmap task no longer demands masscan just to get started.
    """
    scan_type = task["scan_type"] or "full"
    needed = set()

    if task["discovery"]:
        profile = discovery.get_profile(task["discovery"])
        if profile is None:
            raise ScanError(f"Unknown discovery method: {task['discovery']!r}")
        # The reuse option runs nothing, so it needs nothing installed.
        if profile.tool:
            needed.add(profile.tool)
        # Checked before the privilege check: "this range is too big for hping3"
        # is more useful than "hping3 needs root" when both are true.
        too_big = discovery.check_host_cap(profile, task["target"],
                                           count_targets(task["target"]))
        if too_big:
            raise ScanError(too_big)
    if scan_type == "full":
        engine = task["engine"] or DEFAULT_ENGINE
        if engine not in ("masscan", "nmap", "rustscan"):
            raise ScanError(f"Unknown scan engine: {engine!r}")
        needed.add(engine)
    elif scan_type == "quick":
        needed.add("nmap")
    elif scan_type == "discovery" and not task["discovery"]:
        raise ScanError("A host-discovery task needs a discovery method selected.")

    for tool in sorted(needed):
        require_tool(tool)

    # masscan and hping3 craft raw packets and need the privilege; nmap degrades
    # gracefully without it. Distributions often ship fping with cap_net_raw, so
    # check the binary rather than assuming root is required.
    if os.geteuid() == 0 or _inherits_cap_net_raw():
        return
    blocked = sorted(t for t in needed
                     if t in ("masscan", "fping", "hping3") and not _has_raw_caps(t))
    if blocked:
        raise ScanError(
            f"{', '.join(blocked)} need raw sockets — run this tool as root "
            f"(e.g. 'sudo python scanner.py'), or pick an nmap-based scan, "
            f"which works unprivileged with reduced probe types.")


def _inherits_cap_net_raw():
    """True when child processes will inherit CAP_NET_RAW from this one.

    The packaged systemd unit runs as an unprivileged user with
    AmbientCapabilities=CAP_NET_RAW, which children keep across exec. Only the
    *ambient* set carries over like that, so checking the effective set here
    would wrongly green-light scanners that then fail with permission denied.
    """
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapAmb:"):
                    return bool(int(line.split()[1], 16) & (1 << CAP_NET_RAW))
    except (OSError, ValueError, IndexError):
        pass
    return False


def _has_raw_caps(tool):
    """True if the binary can already open raw sockets without root.

    Covers file capabilities (cap_net_raw, how fping usually ships) and the
    older setuid-root approach.
    """
    path = shutil.which(tool)
    if not path:
        return False
    try:
        if os.stat(path).st_mode & stat.S_ISUID:
            return True
    except OSError:
        return False
    # security.capability is a packed vfs_cap_data struct: a magic word followed
    # by permitted/inheritable masks. CAP_NET_RAW is bit 13 of the low word.
    try:
        blob = os.getxattr(path, "security.capability")
    except OSError:
        return False
    if len(blob) < 12:
        return False
    _magic, permitted_lo, _inheritable_lo = struct.unpack_from("<III", blob, 0)
    return bool(permitted_lo & (1 << CAP_NET_RAW))


class ScanManager:
    """Owns the running scan, its subscribers, and the connectivity watchdog."""

    def __init__(self):
        self._lock = threading.RLock()
        self._active_task = None
        self._subs = {}            # task_id -> list[queue.Queue]
        self._taps = []            # callbacks that see every published event
        self._net = {"error": False, "disconnected_at": None, "reconnected_at": None}
        self._auto_paused = False
        self._stopping = set()     # tasks the user stopped, so we don't call it an error
        self._threads = {}         # task_id -> the thread running its sweep
        self._rescans = {}         # task_id -> {ip: tool} currently being rescanned
        self._rescan_cancels = set()   # (task_id, ip) pairs the user asked to stop
        self._progress_written = {}
        self._watchdog = None

    # --- pub/sub ---------------------------------------------------------

    def subscribe(self, task_id):
        q = queue.Queue(maxsize=2000)
        with self._lock:
            self._subs.setdefault(task_id, []).append(q)
        return q

    def unsubscribe(self, task_id, q):
        with self._lock:
            subs = self._subs.get(task_id)
            if subs and q in subs:
                subs.remove(q)
            if subs is not None and not subs:
                self._subs.pop(task_id, None)

    def add_event_tap(self, callback):
        """Registers a callback that sees every published event, task-agnostic.

        Notifications are derived from the same events the page streams, in one
        place, rather than raised by hand at each call site — so a new event
        cannot quietly go unreported and the engine keeps knowing nothing about
        the notification layer.
        """
        with self._lock:
            self._taps.append(callback)

    def publish(self, task_id, event):
        with self._lock:
            subs = list(self._subs.get(task_id, []))
            taps = list(self._taps)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass   # a browser tab that stopped reading must not stall the scan
        for tap in taps:
            try:
                tap(task_id, event)
            except Exception:      # noqa: BLE001 - a tap must never break a scan
                pass

    def log(self, task_id, line):
        """Publishes a scanner output line and appends it to the task's log file.

        Persisting matters: without it a reload leaves you with an empty output
        panel and no way to see why a scan found nothing.
        """
        self.publish(task_id, {"type": "log", "line": line})
        try:
            with open(log_path(task_id), "a") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    # --- state -----------------------------------------------------------

    @property
    def active_task(self):
        with self._lock:
            return self._active_task

    def network_state(self):
        with self._lock:
            return dict(self._net)

    def is_paused(self, task_id):
        return registry.is_paused(task_id)

    # --- lifecycle -------------------------------------------------------

    def start(self, task_id, resume=False):
        """Launches the scan in a background thread. Raises ScanBusy/ScanError."""
        task = store.get_task(task_id)
        if task is None:
            raise ScanError("Task not found.")
        _check_requirements(task)

        with self._lock:
            if self._active_task and self._active_task != task_id:
                other = store.get_task(self._active_task)
                label = (other["name"] if other else self._active_task)
                raise ScanBusy(
                    f"Another scan is already running ('{label}'). masscan saturates "
                    f"the link, so only one sweep runs at a time — stop that one first.")
            if self._active_task == task_id:
                raise ScanBusy("This task is already running.")
            self._active_task = task_id

        store.update_task(task_id, status="running", started_at=now(),
                          finished_at=None, error=None, progress=0.0)
        thread = threading.Thread(target=self._run_task, args=(task_id, resume),
                                  name=f"scan-{task_id}", daemon=True)
        with self._lock:
            self._threads[task_id] = thread
        thread.start()
        self.ensure_watchdog()
        return thread

    def pause(self, task_id):
        n = registry.pause(task_id)
        if not n:
            # Nothing was actually running — the scan finished before the click
            # landed. Leave the recorded status alone rather than marking a
            # completed task as paused.
            registry.resume(task_id)
            return 0
        store.update_task(task_id, status="paused")
        self.publish(task_id, {"type": "status", "status": "paused",
                               "message": f"Paused {n} running process(es)."})
        return n

    def resume(self, task_id):
        with self._lock:
            self._auto_paused = False
            self._net["error"] = False
        n = registry.resume(task_id)
        if registry.is_running(task_id):
            store.update_task(task_id, status="running")
            self.publish(task_id, {"type": "status", "status": "running",
                                   "message": "Resumed."})
        return n

    def stop(self, task_id):
        """Interrupts this task only. masscan gets a chance to write paused.conf."""
        with self._lock:
            self._stopping.add(task_id)
            thread = self._threads.get(task_id)
        n = registry.stop(task_id, grace=STOP_GRACE_SECONDS)
        # Let the sweep thread finish draining output and write its final status,
        # so whoever called this reads a settled state rather than "running".
        if thread and thread.is_alive():
            thread.join(timeout=15)
        if n:
            self.publish(task_id, {"type": "status", "status": "stopped",
                                   "message": "Scan stopped."})
        return n

    # --- rescans ---------------------------------------------------------

    def active_rescans(self, task_id):
        with self._lock:
            return dict(self._rescans.get(task_id, {}))

    def start_rescan(self, task_id, ip, tool, project_id=None):
        """Runs a per-host rescan in the background.

        These used to block the HTTP request for their whole duration — fine for
        the 60s case, not for a slow host where the browser would simply give up
        and the user would never learn the result. Now the request returns at
        once and the outcome arrives over the task's event stream.
        """
        with self._lock:
            running = self._rescans.setdefault(task_id, {})
            if ip in running:
                raise ScanBusy(f"A {running[ip]} rescan of {ip} is already running.")
            running[ip] = tool
            self._rescan_cancels.discard((task_id, ip))

        def cancelled():
            with self._lock:
                return (task_id, ip) in self._rescan_cancels

        # What this host already had, so "new port" means it rather than a guess
        # at how many the rescan happened to report.
        before = {f"{p['port']}/{p['proto']}"
                  for h in store.task_hosts(task_id) if h["ip"] == ip
                  for p in h["ports"]}

        def worker():
            self.publish(task_id, {"type": "rescan", "state": "running",
                                   "ip": ip, "tool": tool})
            try:
                entry = rescan_tool(tool)
                if entry is None:
                    raise ScanError(f"Unknown tool: {tool}")
                result = entry["run"](ip, {"task_id": task_id,
                                           "project_id": project_id,
                                           "cancelled": cancelled})
            except ScanCancelled as exc:
                self.log(task_id, f"[i] {exc}")
                self.publish(task_id, {"type": "rescan", "state": "cancelled",
                                       "ip": ip, "tool": tool, "message": str(exc)})
                return
            except (ScanError, OSError) as exc:
                self.log(task_id, f"[!] Rescan of {ip} failed: {exc}")
                self.publish(task_id, {"type": "rescan", "state": "error",
                                       "ip": ip, "tool": tool, "error": str(exc)})
                return
            except Exception as exc:                  # noqa: BLE001 - shown in the UI
                msg = f"{type(exc).__name__}: {exc}"
                self.log(task_id, f"[!] Rescan of {ip} failed: {msg}")
                self.publish(task_id, {"type": "rescan", "state": "error",
                                       "ip": ip, "tool": tool, "error": msg})
                return
            finally:
                with self._lock:
                    self._rescans.get(task_id, {}).pop(ip, None)
                    self._rescan_cancels.discard((task_id, ip))

            # Hand back the merged view so the card shows nmap services layered
            # over the ports masscan found.
            merged = next((h["ports"] for h in store.task_hosts(task_id)
                           if h["ip"] == ip), result.get("ports", []))
            fresh = [p for p in merged
                     if f"{p['port']}/{p['proto']}" not in before]
            note = result.get("note")
            verb = "stopped" if result.get("stopped") else "finished"
            self.log(task_id, f"Rescan of {ip} ({tool}) {verb}: "
                              f"{len(merged)} port(s)"
                              + (f", {len(fresh)} new" if fresh else "")
                              + (f", {result['screenshots']} screenshot(s)"
                                 if result.get("screenshots") else "")
                              + (f" — {note}" if note else ""))
            self.publish(task_id, {
                "type": "rescan", "state": "done", "ip": ip, "tool": tool,
                "ports": merged, "new_ports": len(fresh),
                "scan_id": result.get("scan_id"),
                "screenshots": result.get("screenshots", 0), "note": note,
                "stopped": bool(result.get("stopped")),
            })

        threading.Thread(target=worker, name=f"rescan-{ip}", daemon=True).start()

    def stop_rescan(self, task_id, ip, settle=5.0):
        """Stops one host's rescan, leaving the sweep and other hosts alone."""
        with self._lock:
            if ip not in self._rescans.get(task_id, {}):
                return False
            self._rescan_cancels.add((task_id, ip))
        registry.stop(rescan_key(task_id, ip), grace=3)

        # Wait for the worker to unwind before reporting back. Otherwise the host
        # still counts as "being rescanned" for a moment, and an immediate second
        # click would be turned away as already running.
        deadline = time.monotonic() + settle
        while time.monotonic() < deadline:
            with self._lock:
                if ip not in self._rescans.get(task_id, {}):
                    break
            time.sleep(0.05)
        return True

    # --- the sweep -------------------------------------------------------

    def _run_task(self, task_id, resume):
        """Orchestrates a task: optional discovery, then the chosen port scan."""
        task = store.get_task(task_id)
        run_dir = _run_dir(task_id)
        scan_type = task["scan_type"] or "full"
        outcome, error = "completed", None

        try:
            # The log accumulates across runs, separated by a header: one task
            # can hold an nmap top-ports pass and a later full masscan sweep, and
            # you want to see both.
            self.log(task_id, "")
            from .scanconfig import describe   # local: scanconfig imports engine
            self.log(task_id, f"══ {now()} · {describe(dict(task))} ══")
            if is_loopback_target(task["target"]):
                self.log(task_id, (
                    "[!] Warning: this target is loopback. masscan uses its own "
                    "TCP/IP stack and transmits via a network adapter, so it "
                    "cannot see services bound to 127.0.0.0/8 — this scan will "
                    "report nothing no matter what is listening. Use nmap for "
                    "localhost, or point this at a routable address."))

            targets = task["target"]

            # --- phase 1: host discovery ---------------------------------
            # Narrowing the port scan to hosts that actually answered is the
            # whole point: a /24 sweep drops from 254 targets to the handful
            # that are really there.
            if task["discovery"] and not resume:
                live = self._phase_discovery(task_id, task, run_dir)
                if live is None:
                    outcome = "stopped"
                    return
                if not live:
                    self.log(task_id, "Discovery found no live hosts — skipping "
                                      "the port scan. Try a different probe type "
                                      "if you expected hosts here.")
                    store.update_task(task_id, progress=100.0)
                    return
                targets = ",".join(h["ip"] for h in live)

            # --- phase 2: port scan --------------------------------------
            if scan_type == "discovery":
                store.update_task(task_id, progress=100.0)
                return
            if scan_type == "quick":
                outcome, error = self._phase_quick(task_id, task, run_dir, targets)
                return

            engine = task["engine"] or DEFAULT_ENGINE
            if engine == "nmap":
                outcome, error = self._phase_quick(task_id, task, run_dir, targets)
            elif engine == "rustscan":
                outcome, error = self._phase_rustscan(task_id, task, run_dir, targets)
            else:
                self._warn_masscan_unreachable(task_id, targets)
                outcome, error = self._phase_masscan(task_id, task, run_dir,
                                                     targets, resume)

        except (ScanError, OSError) as exc:
            outcome, error = "error", str(exc)
        except Exception as exc:                      # noqa: BLE001 - surfaced in the UI
            outcome, error = "error", f"{type(exc).__name__}: {exc}"
        finally:
            self._finish_task(task_id, outcome, error)

    def _phase_discovery(self, task_id, task, run_dir):
        """Finds which addresses are alive. Returns the live hosts, or None if stopped."""
        profile = discovery.get_profile(task["discovery"])
        if profile is None:
            raise ScanError(f"Unknown discovery method: {task['discovery']!r}")

        # Reuse: no probe, no clearing. Everything this task has ever seen alive
        # — discovery hits and hosts that turned up ports — becomes the target.
        if task["discovery"] == discovery.PREVIOUS:
            return self._reuse_previous_hosts(task_id, task)

        require_tool(profile.tool)
        store.clear_hosts(task_id)     # a re-run re-discovers from scratch
        self.publish(task_id, {"type": "phase", "phase": "discovery",
                               "tool": profile.tool, "label": profile.label})
        self.log(task_id, f"[discovery] {profile.label} over {task['target']}")

        found = (self._discover_per_host(task_id, task, profile)
                 if profile.per_host
                 else self._discover_range(task_id, task, run_dir, profile))

        if found is None:
            return None

        store.add_hosts(task_id, found, method=profile.key)
        live = store.live_hosts(task_id)
        self.log(task_id, f"[discovery] {len(live)} host(s) up out of "
                          f"{count_targets(task['target']) or '?'} address(es).")
        self.publish(task_id, {"type": "discovery_done", "count": len(live)})
        return live

    def _reuse_previous_hosts(self, task_id, task):
        """Uses the hosts this task already knows instead of probing again."""
        self.publish(task_id, {"type": "phase", "phase": "discovery",
                               "tool": "none", "label": "Reusing hosts found earlier"})

        # task_hosts is the union of discovery hits and anything with a finding,
        # so a task that only ever ran a port sweep still has a usable list.
        known = [h["ip"] for h in store.task_hosts(task_id)]
        if not known:
            raise ScanError(
                "No hosts from an earlier run of this task, so there is nothing "
                "to reuse. Run a discovery sweep once — fping or nmap — and later "
                "runs can reuse what it finds.")

        # Put them back in the hosts table so the rest of the run, and the host
        # list on the page, work exactly as they would after a real sweep.
        store.add_hosts(task_id, [{"ip": ip, "state": "up",
                                   "reason": "found by an earlier run"}
                                  for ip in known], method=discovery.PREVIOUS)
        live = store.live_hosts(task_id)
        self.log(task_id, f"[discovery] reusing {len(live)} host(s) found "
                          f"earlier — no probe sent.")
        self.publish(task_id, {"type": "discovery_done", "count": len(live)})
        return live

    def _discover_range(self, task_id, task, run_dir, profile):
        cmd, kind = discovery.build_command(profile, task["target"], run_dir,
                                            rate=task["rate"])
        self.log(task_id, "$ " + " ".join(cmd))
        proc = registry.spawn(task_id, cmd, cwd=run_dir)
        streamed = []
        try:
            stderr_thread = threading.Thread(
                target=self._pump_stderr, args=(task_id, proc), daemon=True)
            stderr_thread.start()
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                if kind == "stdout_ips":
                    # fping prints live addresses as it gets replies.
                    for host in discovery.parse_ip_lines(line):
                        streamed.append(host)
                        self._publish_host(task_id, host, profile.key)
                    continue
                if kind == "masscan_list":
                    hit = parse_discovery_line(line)
                    if hit:
                        host = {"ip": hit["ip"], "state": "up", "reason": "icmp-reply"}
                        streamed.append(host)
                        self._publish_host(task_id, host, profile.key)
                        continue
                self.log(task_id, line)
            proc.wait()
            stderr_thread.join(timeout=5)
        finally:
            registry.release(task_id, proc)

        with self._lock:
            if task_id in self._stopping:
                return None

        if kind == "nmap_xml":
            try:
                with open(os.path.join(run_dir, "discovery.xml")) as fh:
                    hosts = discovery.parse_nmap_hosts(fh.read())
            except OSError:
                hosts = []
            for host in hosts:
                self._publish_host(task_id, host, profile.key)
            return hosts

        if kind == "masscan_list":
            hosts = {h["ip"]: h for h in streamed}
            for host in discovery.parse_masscan_pings(
                    os.path.join(run_dir, "discovery.list")):
                hosts.setdefault(host["ip"], host)
            return list(hosts.values())

        # fping exits non-zero whenever anything was unreachable, which is the
        # normal outcome of a sweep, so its return code says nothing useful.
        return list({h["ip"]: h for h in streamed}.values())

    def _discover_per_host(self, task_id, task, profile):
        ips = discovery.expand_targets(task["target"])
        too_big = discovery.check_host_cap(profile, task["target"], len(ips))
        if too_big:
            raise ScanError(too_big)

        def spawn(cmd):
            return registry.spawn(task_id, cmd, cwd=_run_dir(task_id))

        def stopping():
            with self._lock:
                return task_id in self._stopping

        found = discovery.run_per_host(
            profile, ips, spawn,
            log=lambda msg: self.log(task_id, f"[discovery] {msg}"),
            should_stop=stopping)
        if stopping():
            return None
        for host in found:
            self._publish_host(task_id, host, profile.key)
        return found

    def _publish_host(self, task_id, host, method):
        self.publish(task_id, {
            "type": "discovered", "ip": host["ip"],
            "hostname": host.get("hostname"), "reason": host.get("reason"),
            "method": method,
        })

    def _phase_quick(self, task_id, task, run_dir, targets):
        """nmap-only port scan: top-N by default, or an explicit range.

        Slower than masscan but retransmits, so it does not lose ports to packet
        loss the way a stateless single-SYN sweep does.
        """
        require_tool("nmap")
        target_args = discovery._target_args(targets, run_dir, "quick")
        # An explicit range wins over top-ports: that is how you ask for the
        # accurate full sweep (1-65535) when masscan's results look doubtful.
        if task["tcp_ports"]:
            port_args = ["-p", task["tcp_ports"]]
        else:
            port_args = ["--top-ports", str(int(task["top_ports"] or DEFAULT_TOP_PORTS))]

        # Which protocols to sweep. -sU needs root, which this build has; the
        # scanners inherit it. -sT and -sU together is one nmap run covering
        # both, and --top-ports then means the top N of each protocol.
        proto = task["quick_proto"] or "tcp"
        proto_args = {"udp": ["-sU"], "both": ["-sT", "-sU"]}.get(proto, ["-sT"])
        cmd = ["nmap", *proto_args, "-sV", "-T4", "-Pn", "-n", *port_args,
               "--stats-every", "5s", "-oX", "quick.xml", *target_args]

        if proto != "tcp":
            self.log(task_id, f"[i] Quick scan covering "
                              f"{'TCP and UDP' if proto == 'both' else 'UDP'}.")
        self.log(task_id, "$ " + " ".join(cmd))
        self.publish(task_id, {"type": "phase", "phase": "portscan", "tool": "nmap"})

        proc = registry.spawn(task_id, cmd, cwd=run_dir)
        try:
            stderr_thread = threading.Thread(
                target=self._pump_stderr, args=(task_id, proc), daemon=True)
            stderr_thread.start()
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                pct = parse_nmap_progress(line)
                if pct is not None:
                    self._maybe_persist_progress(task_id, pct)
                    self.publish(task_id, {"type": "progress", "percent": pct,
                                           "rate_kpps": 0, "remaining": None,
                                           "found": None})
                else:
                    self.log(task_id, line)
            proc.wait()
            stderr_thread.join(timeout=5)
        finally:
            registry.release(task_id, proc)

        try:
            with open(os.path.join(run_dir, "quick.xml")) as fh:
                by_host = parse_nmap_xml(fh.read())
        except OSError:
            by_host = {}

        seen = {h["ip"] for h in store.task_hosts(task_id)}
        for ip, ports in by_host.items():
            if not ports:
                continue
            store.add_findings(task_id, ip, ports, source="nmap")
            for port in ports:
                self.publish(task_id, {
                    "type": "host", "ip": ip, "new_host": ip not in seen,
                    "port": port})
                seen.add(ip)

        with self._lock:
            if task_id in self._stopping:
                return "stopped", None
        if proc.returncode not in (0, None):
            detail = _last_meaningful_line(read_log(task_id))
            return "error", (f"nmap exited with code {proc.returncode}."
                             + (f" Last output: {detail}" if detail else ""))
        store.update_task(task_id, progress=100.0)
        return "completed", None

    def _warn_masscan_unreachable(self, task_id, targets):
        """Says up front when masscan physically cannot reach the target.

        Otherwise the run looks successful and simply reports nothing, which is
        the single most misleading result this tool can produce.
        """
        networks = ipsec_out_networks()
        first = next(iter(discovery.expand_targets(targets, limit=1)), None)
        if not first:
            return
        ok, reason = masscan_reachability(first, ipsec_networks=networks)
        if not ok:
            self.log(task_id, f"[!] masscan is very unlikely to work here: {reason}")

    def _phase_rustscan(self, task_id, task, run_dir, targets):
        """rustscan: fast full-range TCP connect scan.

        Unlike masscan it uses ordinary kernel sockets, so it works over IPsec,
        WireGuard and any other tunnel the kernel handles — at the cost of being
        slower and TCP-only.
        """
        require_tool("rustscan")
        ports = task["tcp_ports"] or DEFAULT_TCP_PORTS
        addresses = discovery.expand_targets(targets, limit=4096)
        if not addresses:
            raise ScanError(f"Could not expand {targets!r} into addresses for rustscan.")

        cmd = ["rustscan", "-a", ",".join(addresses), "--no-banner", "-n",
               "-g", "--scripts", "none",
               "-b", str(RUSTSCAN_BATCH), "-u", str(RUSTSCAN_ULIMIT),
               "-t", str(RUSTSCAN_TIMEOUT_MS), "--tries", str(RUSTSCAN_TRIES)]
        # rustscan takes either a range or an explicit list, never both.
        if "," in ports or "-" not in ports:
            cmd += ["-p", ports]
        else:
            cmd += ["-r", ports]
        if task["udp_ports"]:
            self.log(task_id, "[i] rustscan is TCP-only — the UDP range is ignored. "
                              "Use masscan or nmap for UDP.")

        self.log(task_id, "$ " + " ".join(cmd[:8]) + " ...")
        self.publish(task_id, {"type": "phase", "phase": "portscan",
                               "tool": "rustscan"})

        seen = {h["ip"] for h in store.task_hosts(task_id)}
        proc = registry.spawn(task_id, cmd, cwd=run_dir)
        try:
            stderr_thread = threading.Thread(
                target=self._pump_stderr, args=(task_id, proc), daemon=True)
            stderr_thread.start()
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                hit = parse_rustscan_line(line)
                if not hit:
                    self.log(task_id, line)
                    continue
                ip, found = hit
                store.add_findings(task_id, ip,
                                   [{"port": p, "proto": "tcp", "state": "open"}
                                    for p in found], source="rustscan")
                for port in found:
                    self.publish(task_id, {
                        "type": "host", "ip": ip, "new_host": ip not in seen,
                        "port": {"port": port, "proto": "tcp", "state": "open"}})
                    seen.add(ip)
            proc.wait()
            stderr_thread.join(timeout=5)
        finally:
            registry.release(task_id, proc)

        with self._lock:
            if task_id in self._stopping:
                return "stopped", None
        if proc.returncode not in (0, None):
            detail = _last_meaningful_line(read_log(task_id))
            return "error", (f"rustscan exited with code {proc.returncode}."
                             + (f" Last output: {detail}" if detail else ""))
        store.update_task(task_id, progress=100.0)
        return "completed", None

    def _phase_masscan(self, task_id, task, run_dir, targets, resume):
        list_path = os.path.join(run_dir, "findings.list")
        paused_conf = paused_conf_path(task_id)
        seen_hosts = {h["ip"] for h in store.task_hosts(task_id)}
        outcome, error = "completed", None
        # Remembering the mtime lets us tell a paused.conf this run just wrote
        # (a real stop) from one left over from a previous run (a failed resume).
        paused_before = _mtime(paused_conf)

        dropped = []
        if resume:
            if not os.path.exists(paused_conf):
                raise ScanError("No paused.conf saved for this task — nothing to resume.")
            dropped = sanitize_paused_conf(paused_conf)
            cmd = ["masscan", "--resume", os.path.basename(paused_conf)]
        else:
            spec = build_port_spec(task["tcp_ports"], task["udp_ports"])
            rate = str(task["rate"] or DEFAULT_RATE)
            retries = task["retries"]
            retries = DEFAULT_RETRIES if retries is None else int(retries)
            wait = task["wait"] or MASSCAN_WAIT
            cmd = ["masscan", *targets.split(","), "-p", spec,
                   "--rate", rate, "--wait", str(wait),
                   "--retries", str(retries),
                   "-oL", os.path.basename(list_path)]
            if retries == 0:
                self.log(task_id, (
                    "[!] retries is 0 — masscan will send a single SYN per port "
                    "and never retransmit. Any dropped probe silently loses that "
                    "port. Raise retries if results look thin."))
            # A stale paused.conf from a previous run would be misleading.
            _unlink(paused_conf)
            _unlink(list_path)

        if dropped:
            self.log(task_id, "[i] Removed config keys masscan cannot read "
                              "back from its own paused.conf: " + "; ".join(dropped))
        self.log(task_id, "$ " + " ".join(cmd))
        self.publish(task_id, {"type": "phase", "phase": "portscan",
                               "tool": "masscan"})

        proc = registry.spawn(task_id, cmd, cwd=run_dir)
        try:
            stderr_thread = threading.Thread(
                target=self._pump_stderr, args=(task_id, proc), daemon=True)
            stderr_thread.start()

            for line in proc.stdout:
                hit = parse_discovery_line(line)
                if hit:
                    self._record_hit(task_id, hit, seen_hosts)
                elif line.strip():
                    self.log(task_id, line.rstrip())

            proc.wait()
            stderr_thread.join(timeout=5)
        finally:
            registry.release(task_id, proc)

        # Backfill from -oL in case stdout was block-buffered or lines were
        # dropped; the file is masscan's own authoritative record.
        for hit in parse_masscan_list_file(list_path):
            self._record_hit(task_id, hit, seen_hosts, quiet_if_known=True)

        with self._lock:
            was_stopped = task_id in self._stopping

        # Only a paused.conf written *by this run* means "resumable". An
        # untouched one is a leftover, and treating it as a stop is how a
        # failed resume used to disguise itself as a successful one.
        paused_written_now = (os.path.exists(paused_conf)
                              and _mtime(paused_conf) != paused_before)

        if paused_written_now:
            store.update_task(task_id, resumable=1)
            return "stopped", None
        if was_stopped:
            return "stopped", None
        if proc.returncode not in (0, None):
            # Not a stop, and masscan saved no new position: it genuinely
            # failed — bad permissions, bad interface, unreadable resume file.
            detail = _last_meaningful_line(read_log(task_id))
            error = f"masscan exited with code {proc.returncode}."
            if detail:
                error += f" Last output: {detail}"
            if resume:
                error += (" The resume file may be unusable — start the scan "
                          "from the beginning instead.")
            return "error", error

        # A clean full sweep supersedes any older resume point.
        _unlink(paused_conf)
        store.update_task(task_id, resumable=0, progress=100.0)
        self._warn_if_thin(task_id, task, targets)
        return "completed", None

    # Ports that a SIP/SCCP-inspecting middlebox (router ALG, VoIP firewall)
    # commonly answers on behalf of a host that is not really listening.
    ALG_PORTS = {2000, 5060, 5061}

    def _warn_if_thin(self, task_id, task, targets):
        """Flags results that look like packet loss rather than a quiet host.

        masscan silently under-reports when probes are dropped, and the failure
        is invisible — you just get fewer ports and no indication anything went
        wrong. Worth saying out loud rather than letting it pass as fact.
        """
        host_count = count_targets(targets) or 1
        found = [p for h in store.task_hosts(task_id) for p in h["ports"]]
        if not found:
            return

        retries = task["retries"]
        retries = DEFAULT_RETRIES if retries is None else int(retries)

        # Only two ports across a whole sweep, and both of them the classic ALG
        # pair, is the signature of a middlebox answering rather than the host.
        ports = {p["port"] for p in found}
        if ports and ports <= self.ALG_PORTS:
            self.log(task_id, (
                f"[!] Every port found ({', '.join(str(p) for p in sorted(ports))}) "
                f"is one a SIP/SCCP application-layer gateway commonly answers "
                f"for. These are frequently NOT open on the host itself — a "
                f"router or VoIP firewall in the path replies instead. Confirm "
                f"with 'nmap -sV -Pn' before trusting them."))

        if retries == 0 and len(found) <= 3 * host_count:
            self.log(task_id, (
                "[!] Few ports found and retries is 0. masscan does not "
                "retransmit, so dropped probes look identical to closed ports. "
                "Re-run with retries 2-3 before concluding the host is quiet."))

    def _finish_task(self, task_id, outcome, error):
        with self._lock:
            if self._active_task == task_id:
                self._active_task = None
            self._stopping.discard(task_id)
            self._threads.pop(task_id, None)
            self._progress_written.pop(task_id, None)
        store.update_task(task_id, status=outcome, finished_at=now(), error=error)
        hosts = store.task_hosts(task_id)
        ports = sum(len(h["ports"]) for h in hosts)
        self.log(task_id, f"Finished: {outcome} — {len(hosts)} host(s), "
                          f"{ports} port(s)." + (f" Error: {error}" if error else ""))
        self.publish(task_id, {
            "type": "done", "status": outcome, "error": error,
            "hosts": len(hosts), "ports": ports,
            "resumable": os.path.exists(paused_conf_path(task_id)),
        })

    def _record_hit(self, task_id, hit, seen_hosts, quiet_if_known=False):
        ip = hit["ip"]
        fresh = store.add_findings(task_id, ip, [hit], source="masscan")
        if not fresh and quiet_if_known:
            return
        is_new_host = ip not in seen_hosts
        seen_hosts.add(ip)
        self.publish(task_id, {
            "type": "host",
            "ip": ip,
            "new_host": is_new_host,
            "port": {"port": hit["port"], "proto": hit["proto"], "state": hit["state"]},
        })

    def _maybe_persist_progress(self, task_id, percent, min_interval=3.0):
        now_ts = time.monotonic()
        with self._lock:
            last = self._progress_written.get(task_id, 0.0)
            if now_ts - last < min_interval:
                return
            self._progress_written[task_id] = now_ts
        store.update_task(task_id, progress=percent)

    def _pump_stderr(self, task_id, proc):
        """masscan repaints its status line with \\r, so read raw and split on both."""
        buf = ""
        try:
            while True:
                chunk = proc.stderr.read(256)
                if not chunk:
                    break
                buf += chunk
                parts = re.split(r"[\r\n]", buf)
                buf = parts.pop()
                for part in parts:
                    part = part.strip()
                    if not part:
                        continue
                    progress = parse_progress_line(part)
                    if progress:
                        # Stream every repaint to the UI, but only persist every
                        # few seconds — masscan repaints several times a second
                        # and a DB write per repaint is pure churn.
                        self._maybe_persist_progress(task_id, progress["percent"])
                        self.publish(task_id, {"type": "progress", **progress})
                    else:
                        self.log(task_id, part)
        except (ValueError, OSError):
            pass

    # --- connectivity watchdog ------------------------------------------

    def ensure_watchdog(self):
        with self._lock:
            if self._watchdog and self._watchdog.is_alive():
                return
            self._watchdog = threading.Thread(target=self._watch_network,
                                              name="net-watchdog", daemon=True)
            self._watchdog.start()

    def _watch_network(self):
        """Freezes the sweep when connectivity drops, and says so once each way.

        Each transition is announced exactly once — the flags are cleared as the
        message is emitted, so a long outage doesn't spam the event stream.
        """
        while True:
            time.sleep(5)
            task_id = self.active_task
            if not task_id:
                continue
            connected = check_internet()

            with self._lock:
                was_error = self._net["error"]
                announce = None
                if not connected and not was_error:
                    self._net.update(error=True, disconnected_at=now(),
                                     reconnected_at=None)
                    if not registry.is_paused(task_id):
                        self._auto_paused = True
                        announce = "lost"
                elif connected and was_error:
                    self._net.update(error=False, reconnected_at=now())
                    # Only invite a resume if the drop is what paused it.
                    announce = "restored" if self._auto_paused else None
                    self._auto_paused = False
                snapshot = dict(self._net)

            if announce == "lost":
                registry.pause(task_id)
                store.update_task(task_id, status="paused")
                self.publish(task_id, {
                    "type": "network", "connected": False,
                    "disconnected_at": snapshot["disconnected_at"],
                    "message": "Network lost — scan paused automatically."})
            elif announce == "restored":
                self.publish(task_id, {
                    "type": "network", "connected": True,
                    "reconnected_at": snapshot["reconnected_at"],
                    "message": "Network restored — press resume to continue."})


def _mtime(path):
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def _last_meaningful_line(text):
    """Last line of scanner output worth quoting in an error message."""
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line and not line.startswith("$ ") and not line.startswith("Finished:"):
            return line[:200]
    return ""


def _unlink(path):
    try:
        os.remove(path)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            pass


manager = ScanManager()


# --- nmap ----------------------------------------------------------------

def rescan_key(task_id, ip):
    """Registry key for one host's rescan.

    Deliberately separate from the task's own key: a rescan must be stoppable on
    its own, and stopping the sweep must not take a running rescan down with it.
    """
    return f"rescan:{task_id or 'adhoc'}:{ip}"


def _run_nmap(task_id, ip, ports, udp=False, port_selector=None):
    """Runs nmap against a host.

    `ports` is normally the list already found. A full-port rescan passes
    `port_selector=['-p', '-']` and leaves `ports` empty.
    """
    selector = port_selector or ["-p", ",".join(str(p) for p in ports)]
    if udp:
        base = ["nmap", "-sU", "-sV", "-Pn", "-T4", *selector, ip]
    else:
        base = ["nmap", "-sC", "-sV", "-Pn", "-T4", *selector, ip]

    run_dir = _run_dir(task_id or "adhoc")
    xml_name = f"nmap-{uuid.uuid4().hex[:8]}.xml"
    xml_path = os.path.join(run_dir, xml_name)
    cmd = base + ["-oX", xml_name, "-oN", "-"]

    key = rescan_key(task_id, ip)
    proc = registry.spawn(key, cmd, cwd=run_dir)
    try:
        out, err = proc.communicate(timeout=NMAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        registry.stop(key, grace=5)
        out, err = "", f"nmap timed out after {NMAP_TIMEOUT}s and was terminated."
    finally:
        registry.release(key, proc)

    normal_out = out or ""
    if err:
        normal_out += "\n" + err

    parsed = []
    try:
        with open(xml_path) as fh:
            by_host = parse_nmap_xml(fh.read())
        parsed = by_host.get(ip) or next(iter(by_host.values()), [])
    except OSError:
        pass
    finally:
        _unlink(xml_path)

    return normal_out, parsed, " ".join(cmd)


def nmap_rescan(ip, tool, task_id=None, project_id=None, cancelled=None):
    """Deep-scans one host over its known-open ports and stores the full report.

    `cancelled` is a callable checked between phases. Stopping during nmap
    discards the run — its output was cut off mid-scan and is not worth keeping.
    Stopping during the screenshot pass keeps the nmap results, since those are
    already complete and only the browser work was abandoned.
    """
    require_tool("nmap")
    cancelled = cancelled or (lambda: False)

    known = []
    if task_id:
        for host in store.task_hosts(task_id):
            if host["ip"] == ip:
                known = host["ports"]
                break
    if not known:
        raise ScanError(
            "No discovered ports for this host yet. Run a masscan sweep first so "
            "nmap knows which ports to inspect.")

    tcp_ports = sorted({p["port"] for p in known if p.get("proto") == "tcp"})
    udp_ports = sorted({p["port"] for p in known if p.get("proto") == "udp"})
    if udp_ports and os.geteuid() != 0:
        udp_ports = []   # -sU needs root; skip rather than fail the whole rescan

    discovered, sections, commands = [], [], []
    if tcp_ports:
        out, parsed, cmd = _run_nmap(task_id, ip, tcp_ports, udp=False)
        discovered += parsed
        sections.append(f"# TCP service/script scan on ports: {','.join(map(str, tcp_ports))}\n{out}")
        commands.append(cmd)
    if cancelled():
        raise ScanCancelled(f"Rescan of {ip} stopped during the nmap scan.")
    if udp_ports:
        out, parsed, cmd = _run_nmap(task_id, ip, udp_ports, udp=True)
        discovered += parsed
        sections.append(f"# UDP scan on ports: {','.join(map(str, udp_ports))}\n{out}")
        commands.append(cmd)
    if cancelled():
        raise ScanCancelled(f"Rescan of {ip} stopped during the nmap scan.")

    scan_id = uuid.uuid4().hex[:12]
    # Browsers are spawned through the registry so a stop reaches them too —
    # a headless capture can hang for the full timeout on an unresponsive host.
    shots, note = shots_mod.capture(
        ip, discovered, scan_id,
        spawn=lambda cmd, **kw: registry.spawn(rescan_key(task_id, ip), cmd, **kw),
        cancelled=cancelled)
    if note:
        sections.append(f"# Web screenshots: {note}")

    store.save_nmap_scan(scan_id, ip, tool, "\n".join(commands), "\n\n".join(sections),
                         discovered, shots, task_id=task_id, project_id=project_id)
    if task_id and discovered:
        store.replace_findings(task_id, ip, discovered, source="nmap")

    return {"ip": ip, "ports": discovered, "scan_id": scan_id,
            "screenshots": len(shots), "note": note,
            "stopped": cancelled()}


def masscan_rescan(ip, proto, task_id=None, rate=5000, cancelled=None):
    """One-shot full-port masscan against a single host."""
    require_tool("masscan")
    cancelled = cancelled or (lambda: False)
    if os.geteuid() != 0 and not _inherits_cap_net_raw():
        raise ScanError("masscan needs root. Restart this tool with sudo.")

    spec = "T:1-65535" if proto == "tcp" else "U:1-65535"
    run_dir = _run_dir(task_id or "adhoc")
    key = rescan_key(task_id, ip)
    cmd = ["masscan", ip, "-p", spec, "--rate", str(rate), "--wait", str(MASSCAN_WAIT)]
    proc = registry.spawn(key, cmd, cwd=run_dir)
    try:
        out, _ = proc.communicate(timeout=NMAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        registry.stop(key, grace=5)
        out = ""
    finally:
        registry.release(key, proc)

    if cancelled():
        raise ScanCancelled(f"Rescan of {ip} stopped.")

    ports = parse_masscan_stdout(out)
    if task_id:
        store.add_findings(task_id, ip, ports, source="masscan")
    return {"ip": ip, "ports": ports}


def nmap_full_rescan(ip, tool, task_id=None, project_id=None, udp=False,
                     cancelled=None):
    """A whole-host nmap rescan, rather than only the ports already known.

    The known-ports scan (nmap_rescan) can only confirm what a sweep already
    found; this is what you reach for when you suspect the sweep under-reported.
    UDP needs root, which this build has.
    """
    require_tool("nmap")
    cancelled = cancelled or (lambda: False)

    # Every TCP port is slow but finishes. Every UDP port is not: nmap sends one
    # probe per port and waits for an ICMP unreachable that rate-limited hosts
    # emit once a second, so a full UDP sweep is roughly a day per host. Cap it.
    selector = ["--top-ports", "200"] if udp else ["-p", "-"]
    out, parsed, cmd = _run_nmap(task_id, ip, [], udp=udp, port_selector=selector)
    if cancelled():
        raise ScanCancelled(f"Rescan of {ip} stopped during the nmap scan.")

    heading = ("# UDP service scan over nmap's top 200 ports" if udp
               else "# TCP service/script scan over every port (-p-)")
    scan_id = uuid.uuid4().hex[:12]
    shots, note = shots_mod.capture(
        ip, parsed, scan_id,
        spawn=lambda cmd, **kw: registry.spawn(rescan_key(task_id, ip), cmd, **kw),
        cancelled=cancelled)
    sections = [f"{heading}\n{out}"]
    if note:
        sections.append(f"# Web screenshots: {note}")

    store.save_nmap_scan(scan_id, ip, tool, cmd, "\n\n".join(sections),
                         parsed, shots, task_id=task_id, project_id=project_id)
    if task_id and parsed:
        store.replace_findings(task_id, ip, parsed, source="nmap")

    return {"ip": ip, "ports": parsed, "scan_id": scan_id,
            "screenshots": len(shots), "note": note, "stopped": cancelled()}


def rustscan_rescan(ip, task_id=None, cancelled=None):
    """Full-port TCP rescan of one host with rustscan.

    Kernel sockets, so it reaches hosts behind an IPsec/VPN tunnel that masscan
    cannot, and needs no privilege.
    """
    require_tool("rustscan")
    cancelled = cancelled or (lambda: False)

    run_dir = _run_dir(task_id or "adhoc")
    key = rescan_key(task_id, ip)
    cmd = ["rustscan", "-a", ip, "--no-banner", "-n", "-g", "--scripts", "none",
           "-r", "1-65535", "-b", str(RUSTSCAN_BATCH), "-u", str(RUSTSCAN_ULIMIT),
           "-t", str(RUSTSCAN_TIMEOUT_MS), "--tries", str(RUSTSCAN_TRIES)]
    proc = registry.spawn(key, cmd, cwd=run_dir)
    try:
        out, _ = proc.communicate(timeout=NMAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        registry.stop(key, grace=5)
        out = ""
    finally:
        registry.release(key, proc)

    if cancelled():
        raise ScanCancelled(f"Rescan of {ip} stopped.")

    ports = []
    for line in (out or "").splitlines():
        hit = parse_rustscan_line(line)
        if hit:
            for port in hit[1]:
                ports.append({"port": port, "proto": "tcp", "state": "open"})
    if task_id:
        store.add_findings(task_id, ip, ports, source="rustscan")
    return {"ip": ip, "ports": ports}


# Every per-host rescan the interface can offer. Defined here so the dropdown
# and the code that runs it cannot drift apart, and so a tool that is not
# installed can be marked unavailable rather than failing only after a click.
RESCAN_TOOLS = [
    {"key": "nmap_deep", "label": "nmap -sC -sV (known ports)", "tool": "nmap",
     "note": "Service and script scan over the ports already found, plus web "
             "screenshots. The usual follow-up.",
     "run": lambda ip, o: nmap_rescan(ip, "nmap_deep", **o)},
    {"key": "nmap_tcp", "label": "nmap all TCP (-p-)", "tool": "nmap",
     "note": "Every TCP port with service detection. Slow, but the most "
             "trustworthy answer when a sweep looks thin.",
     "run": lambda ip, o: nmap_full_rescan(ip, "nmap_tcp", udp=False, **o)},
    {"key": "nmap_udp", "label": "nmap UDP (top 200)", "tool": "nmap",
     "note": "nmap's top 200 UDP ports. A full UDP sweep would take about a day "
             "per host, so this is capped.",
     "run": lambda ip, o: nmap_full_rescan(ip, "nmap_udp", udp=True, **o)},
    {"key": "rustscan_tcp", "label": "rustscan all TCP", "tool": "rustscan",
     "note": "Every TCP port over kernel sockets: fast, needs no privilege, "
             "and works through IPsec and VPN tunnels.",
     "run": lambda ip, o: rustscan_rescan(ip, task_id=o.get("task_id"),
                                          cancelled=o.get("cancelled"))},
    {"key": "masscan_tcp", "label": "masscan all TCP", "tool": "masscan",
     "note": "Fastest full TCP sweep. Needs root and cannot cross a tunnel.",
     "run": lambda ip, o: masscan_rescan(ip, "tcp", task_id=o.get("task_id"),
                                         cancelled=o.get("cancelled"))},
    {"key": "masscan_udp", "label": "masscan all UDP", "tool": "masscan",
     "note": "Every UDP port at masscan speed. Needs root and cannot cross a tunnel.",
     "run": lambda ip, o: masscan_rescan(ip, "udp", task_id=o.get("task_id"),
                                         cancelled=o.get("cancelled"))},
]


def rescan_tool(key):
    return next((t for t in RESCAN_TOOLS if t["key"] == key), None)


def rescan_tools_for_ui():
    """The list the dropdown shows, with availability resolved here."""
    from shutil import which
    return [{"key": t["key"], "label": t["label"], "tool": t["tool"],
             "note": t["note"], "available": which(t["tool"]) is not None}
            for t in RESCAN_TOOLS]
