"""Paths and tuning knobs. Everything here can be overridden by env vars."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A packaged install puts the code under /usr, which is read-only, so its state
# belongs in /var/lib. Running from a checkout keeps everything alongside the
# source, which is what you want while developing.
_SYSTEM_INSTALL = BASE_DIR.startswith(("/usr/lib/", "/usr/share/", "/opt/"))
DATA_DIR = os.environ.get(
    "SLOTH_DATA",
    "/var/lib/sloth" if _SYSTEM_INSTALL else BASE_DIR)

DB_PATH = os.environ.get("SLOTH_DB", os.path.join(DATA_DIR, "scans.db"))
SHOTS_DIR = os.environ.get("SLOTH_SHOTS", os.path.join(DATA_DIR, "screenshots"))
# Each scan task gets a working directory here; masscan drops its paused.conf in it,
# which is what makes --resume possible without tasks stepping on each other.
RUNS_DIR = os.environ.get("SLOTH_RUNS", os.path.join(DATA_DIR, "runs"))

# Ceiling on an imported export. Screenshots travel inside it base64-encoded,
# so a real engagement can run to tens of megabytes; the cap is here to stop an
# accidental upload of something enormous, not to be tight.
MAX_UPLOAD_MB = int(os.environ.get("SLOTH_MAX_UPLOAD_MB", "192"))

HOST = os.environ.get("SLOTH_HOST", "127.0.0.1")
PORT = int(os.environ.get("SLOTH_PORT", "9998"))
# Off by default: this tool needs root for masscan, and the Werkzeug debugger
# would hand a shell to anyone who can reach the port.
DEBUG = os.environ.get("SLOTH_DEBUG", "").lower() in ("1", "true", "yes", "on")

DEFAULT_RATE = int(os.environ.get("SLOTH_RATE", "1000"))
DEFAULT_TCP_PORTS = "1-65535"
DEFAULT_UDP_PORTS = "1-65535"
DEFAULT_TOP_PORTS = 1000   # what a "quick" nmap scan covers, matching nmap's default
DEFAULT_DISCOVERY = "nmap_default"
DEFAULT_ENGINE = "masscan"

# rustscan tuning: it opens a lot of sockets at once, so the ulimit matters.
RUSTSCAN_BATCH = int(os.environ.get("SLOTH_RUSTSCAN_BATCH", "4500"))
RUSTSCAN_ULIMIT = int(os.environ.get("SLOTH_RUSTSCAN_ULIMIT", "5000"))
RUSTSCAN_TIMEOUT_MS = int(os.environ.get("SLOTH_RUSTSCAN_TIMEOUT", "1500"))
RUSTSCAN_TRIES = int(os.environ.get("SLOTH_RUSTSCAN_TRIES", "2"))

# masscan defaults to zero retries: one SYN per port, no retransmission. Against
# any host that drops packets (a firewalled Windows box, a rate-limiting router)
# a single lost probe silently loses the port forever. Retrying is the single
# biggest accuracy win available, at a proportional cost in packets and time.
DEFAULT_RETRIES = 3
# masscan's own default wait is 10s; the previous 5 risked discarding late
# SYN/ACKs from slow or filtered paths.
MASSCAN_WAIT = int(os.environ.get("SLOTH_WAIT", "10"))
STOP_GRACE_SECONDS = 12   # time masscan gets to write paused.conf after SIGINT
NMAP_TIMEOUT = 3600       # hard ceiling on a single nmap invocation
SCREENSHOT_TIMEOUT = 45

# TCP ports treated as web even when nmap can't name the service.
WEB_PORTS = {80, 81, 443, 591, 3000, 5000, 7001, 8000, 8008, 8080, 8081,
             8443, 8888, 9000, 9090, 9200, 10000}

def _ensure_dir(path, label):
    """Creates a data directory, explaining clearly if it cannot.

    A packaged install runs as an unprivileged service account, so a wrong
    owner on /var/lib/sloth is a realistic failure — better a plain
    sentence than an import-time traceback.
    """
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        raise SystemExit(
            f"[!] Cannot create the {label} directory {path}: {exc}\n"
            f"    Fix its ownership (the packaged service runs as the "
            f"'sloth' user), or point SLOTH_DATA somewhere writable."
        ) from exc


_ensure_dir(SHOTS_DIR, "screenshots")
_ensure_dir(RUNS_DIR, "run")
