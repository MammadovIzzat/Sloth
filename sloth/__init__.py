"""Sloth — masscan/nmap front-end with project-based result storage."""
import atexit
import hmac
import os
import secrets
from datetime import timedelta

from flask import Flask, g, jsonify, request, session

from . import store
from .config import BASE_DIR, MAX_UPLOAD_MB, RUNS_DIR
from .db import init_db
from .procs import registry

__version__ = "2.1.0"


def _secret_key():
    """Signs the session cookie that carries the CSRF token.

    Kept on disk so a server restart doesn't invalidate every open page's token.
    """
    env = os.environ.get("SLOTH_SECRET")
    if env:
        return env.encode()
    path = os.path.join(RUNS_DIR, ".secret")
    try:
        with open(path, "rb") as fh:
            key = fh.read().strip()
        if len(key) >= 32:
            return key
    except OSError:
        pass
    key = secrets.token_bytes(48)
    try:
        with open(path, "wb") as fh:
            fh.write(key)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _static_fingerprint(folder):
    """Newest mtime across static files, as a short cache-busting token."""
    newest = 0
    for root, _dirs, files in os.walk(folder or ""):
        for name in files:
            try:
                newest = max(newest, os.stat(os.path.join(root, name)).st_mtime_ns)
            except OSError:
                pass
    return str(newest)[-10:] or "0"


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "templates"),
        static_folder=os.path.join(BASE_DIR, "static"),
    )
    app.config["JSON_SORT_KEYS"] = False
    app.secret_key = _secret_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,      # keep the cookie away from page scripts
        SESSION_COOKIE_SAMESITE="Lax",     # blocks cross-site form posts riding the session
        # Not forcing Secure: the tool serves plain HTTP on localhost by default,
        # and a Secure cookie would simply never be sent.
        SESSION_COOKIE_SECURE=bool(os.environ.get("SLOTH_HTTPS")),
        PERMANENT_SESSION_LIFETIME=timedelta(
            hours=int(os.environ.get("SLOTH_SESSION_HOURS", "12"))),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
    )

    init_db()
    # Anything marked running in the DB died with the previous process.
    store.reset_stale_tasks()

    from .auth import bp as auth_bp, current_user, load_user, require_login
    from .views.projects import bp as projects_bp
    from .views.scan import bp as scan_bp
    from .views.reports import bp as reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(projects_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(reports_bp)

    # Identify the caller first, then refuse anything unauthenticated. Both run
    # before the CSRF check so an anonymous request never reaches it.
    app.before_request(load_user)
    app.before_request(require_login)
    app.jinja_env.globals["current_user"] = current_user

    @app.template_filter("shortdate")
    def shortdate(value):
        return (value or "")[5:16]

    # Static assets are versioned by mtime, so a changed stylesheet is fetched
    # instead of served from cache. A stale sloth.css is indistinguishable from
    # a layout bug, which is a bad way to spend an afternoon.
    _asset_version = _static_fingerprint(app.static_folder)

    @app.context_processor
    def asset_version():
        return {"asset_version": _asset_version}

    @app.context_processor
    def sidebar():
        """The sidebar lists projects on every signed-in page.

        Supplied here rather than threaded through every view, so a new page
        gets the navigation for free. Skipped when signed out — the auth pages
        have no sidebar and the query would be wasted.
        """
        if current_user() is None:
            return {}
        return {"sidebar_projects": store.list_projects(status="active")}

    # --- CSRF ------------------------------------------------------------
    # Without this, any page you happen to visit could POST to this port and
    # start a scan or delete a project. The tool binds to localhost and runs as
    # root, so a stray form submission is worth blocking.

    def csrf_token():
        token = session.get("_csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf"] = token
        return token

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def _check_csrf():
        """Blocks cross-site POSTs without breaking scripted access.

        CSRF is a browser-only attack, and browsers always attach Origin (or at
        least Referer) to a cross-origin POST. So: requests carrying a browser
        origin must be same-origin *and* present a valid token, while curl and
        scripts — which send neither, and cannot be used to forge a request from
        a victim's browser — are left alone. Locking those out would have made
        the tool unscriptable for no security gain.
        """
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None

        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if not origin:
            return None

        if not origin.startswith(request.host_url.rstrip("/")):
            return _reject(f"Cross-origin request from {origin!r} refused.")

        expected = session.get("_csrf")
        supplied = (request.headers.get("X-CSRF-Token")
                    or request.form.get("_csrf")
                    or (request.get_json(silent=True) or {}).get("_csrf"))
        if expected and supplied and hmac.compare_digest(str(expected), str(supplied)):
            return None
        return _reject("CSRF token missing or invalid. Reload the page and try again.")

    def _reject(message):
        if request.is_json or request.path.startswith("/tasks/"):
            return jsonify({"error": message}), 403
        return message, 403

    @app.errorhandler(413)
    def _too_large(_exc):
        # Werkzeug aborts the upload mid-stream, so this must not try to read
        # the request body or redirect back into a form it never received.
        return (f"That upload is larger than the {MAX_UPLOAD_MB} MB limit. "
                f"Raise SLOTH_MAX_UPLOAD_MB if the export really is that big."), 413

    # Never leave a masscan running after the server goes away.
    atexit.register(registry.stop_all)
    return app
