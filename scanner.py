#!/usr/bin/env python3
"""Sloth — entry point.

    sudo python scanner.py

masscan needs raw sockets, so this wants root (or CAP_NET_RAW, which is how the
packaged systemd unit runs it without root). The application itself lives in the
sloth/ package; the previous single-file build is kept alongside as
scanner_v1_backup.py.
"""
import os
import sys

USAGE = """Sloth {version} — masscan/nmap/rustscan front-end

Usage: sloth [--host ADDR] [--port N] [--tls] [--version] [--help]

Options:
  --host ADDR   bind address        (default {host}, env SLOTH_HOST)
  --port N      listen port         (default {port}, env SLOTH_PORT)
  --tls         serve over HTTPS     (env SLOTH_HTTPS)
  --version     print the version and exit
  --help        show this message

Configuration (env vars, or /etc/sloth/sloth.conf when packaged):
  SLOTH_DATA            where results are stored (default {data})
  SLOTH_RATE            default masscan packet rate
  SLOTH_SESSION_HOURS   how long a login lasts
  SLOTH_HTTPS           serve over HTTPS (self-signed cert if none supplied)
  SLOTH_TLS_CERT        path to your own certificate  (PEM)
  SLOTH_TLS_KEY         path to your own private key  (PEM)
  SLOTH_DEBUG           Flask debugger — leave off, it is a remote shell

The first visit creates your account; there is no default password.
Scanners need raw sockets: run as root, or grant CAP_NET_RAW.
"""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # Parsed before the app is built so --help and --version stay instant and
    # cannot be derailed by an unwritable database.
    from sloth import __version__
    from sloth.config import DATA_DIR, DEBUG, HOST, PORT, TLS_ENABLED

    host, port, tls = HOST, PORT, TLS_ENABLED
    while argv:
        arg = argv.pop(0)
        if arg in ("-h", "--help"):
            print(USAGE.format(version=__version__, host=HOST, port=PORT,
                               data=DATA_DIR))
            return 0
        if arg in ("-V", "--version"):
            print(f"sloth {__version__}")
            return 0
        if arg == "--tls":
            tls = True
        elif arg == "--host" and argv:
            host = argv.pop(0)
        elif arg == "--port" and argv:
            try:
                port = int(argv.pop(0))
            except ValueError:
                print("[!] --port needs a number", file=sys.stderr)
                return 2
        else:
            print(f"[!] Unknown option: {arg}\nTry --help.", file=sys.stderr)
            return 2

    from sloth import create_app
    from sloth.db import DatabaseUnavailable
    try:
        app = create_app()
    except DatabaseUnavailable as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    if os.geteuid() != 0:
        print("[!] Not running as root — masscan and fping need raw sockets. "
              "Use sudo, or grant CAP_NET_RAW. nmap and rustscan scans still "
              "work unprivileged.", file=sys.stderr)
    ssl_context = None
    if tls:
        from sloth.tls import ssl_context as build_ssl
        try:
            ssl_context, cert, self_signed = build_ssl(host)
        except RuntimeError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 1
        # When actually serving TLS, mark the session cookie Secure even if the
        # env var was not set — the whole point is that it never leaves TLS.
        app.config["SESSION_COOKIE_SECURE"] = True

    scheme = "https" if ssl_context else "http"
    print(f"[*] Sloth on {scheme}://{host}:{port}")
    if ssl_context:
        print(f"[*] TLS certificate: {cert}"
              + ("  (self-signed — your browser warns once, then accept it)"
                 if self_signed else ""))
    # debug is off unless SLOTH_DEBUG is set: the Werkzeug debugger is a
    # remote shell, and this process is privileged.
    app.run(host=host, port=port, debug=DEBUG, threaded=True, use_reloader=False,
            ssl_context=ssl_context)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
