"""Child-process registry with real pause/resume/stop.

The previous implementation "paused" by checking a threading.Event between scan
phases — a full-port masscan sweep would keep running for as long as it took, and
STOP called `pkill masscan`, killing every masscan on the machine including ones
this tool never started.

Here every child is spawned into its own process group (start_new_session=True)
and tracked against the task that owns it, so signals go to exactly that group:

    pause  -> SIGSTOP   (freezes immediately, mid-sweep)
    resume -> SIGCONT
    stop   -> SIGCONT (in case it was paused), then SIGINT so masscan gets the
              chance to write paused.conf for --resume, then SIGKILL on timeout.
"""
import os
import signal
import subprocess
import threading
import time

from .config import STOP_GRACE_SECONDS


class ProcessRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._procs = {}   # task_id -> list[subprocess.Popen]
        self._paused = set()

    def spawn(self, task_id, cmd, cwd=None, stdout=subprocess.PIPE,
              stderr=subprocess.PIPE, text=True, bufsize=1, env=None):
        """Starts a child in its own process group and registers it under task_id."""
        proc = subprocess.Popen(
            cmd, cwd=cwd, stdout=stdout, stderr=stderr, env=env,
            text=text, bufsize=bufsize, start_new_session=True,
        )
        with self._lock:
            self._procs.setdefault(task_id, []).append(proc)
            # A child started while the task is paused should start paused too.
            paused = task_id in self._paused
        if paused:
            _signal_group(proc, signal.SIGSTOP)
        return proc

    def release(self, task_id, proc):
        with self._lock:
            procs = self._procs.get(task_id)
            if procs and proc in procs:
                procs.remove(proc)
            if procs is not None and not procs:
                self._procs.pop(task_id, None)

    def _live(self, task_id):
        with self._lock:
            return [p for p in self._procs.get(task_id, []) if p.poll() is None]

    def is_running(self, task_id):
        return bool(self._live(task_id))

    def is_paused(self, task_id):
        with self._lock:
            return task_id in self._paused

    def pause(self, task_id):
        with self._lock:
            self._paused.add(task_id)
        count = 0
        for proc in self._live(task_id):
            if _signal_group(proc, signal.SIGSTOP):
                count += 1
        return count

    def resume(self, task_id):
        with self._lock:
            self._paused.discard(task_id)
        count = 0
        for proc in self._live(task_id):
            if _signal_group(proc, signal.SIGCONT):
                count += 1
        return count

    def stop(self, task_id, grace=STOP_GRACE_SECONDS):
        """Interrupts this task's children only. Returns how many were signalled."""
        with self._lock:
            self._paused.discard(task_id)
        procs = self._live(task_id)
        for proc in procs:
            # A SIGSTOPped process cannot act on SIGINT until it is resumed.
            _signal_group(proc, signal.SIGCONT)
            _signal_group(proc, signal.SIGINT)

        deadline = time.monotonic() + grace
        for proc in procs:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                try:
                    proc.wait(timeout=remaining)
                    continue
                except subprocess.TimeoutExpired:
                    pass
            _signal_group(proc, signal.SIGKILL)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        return len(procs)

    def stop_all(self):
        with self._lock:
            task_ids = list(self._procs)
        for task_id in task_ids:
            self.stop(task_id, grace=2)


def _signal_group(proc, sig):
    """Signals the child's whole process group; False if it is already gone."""
    if proc.poll() is not None:
        return False
    try:
        os.killpg(os.getpgid(proc.pid), sig)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        # Fall back to the single pid if the group lookup failed.
        try:
            proc.send_signal(sig)
            return True
        except (ProcessLookupError, OSError):
            return False


registry = ProcessRegistry()
