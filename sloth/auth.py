"""Authentication: session login for the browser, API tokens for scripts.

This tool runs as root, drives raw-socket scanners and stores engagement data,
so leaving the port open to anyone who can reach it is a poor idea — especially
once it is bound to anything other than localhost.

Two ways in:

* **Session login** — a normal form login. The first request to a fresh install
  goes to a setup page to create the account, so there is never a default
  password to forget about.
* **API token** — `Authorization: Bearer <token>` or `X-API-Token`, for curl and
  scripts. Browser CSRF rules do not apply to those, and neither does the login
  redirect, so automation keeps working without weakening the browser path.
"""
import hmac
import secrets
import threading
import time
from functools import wraps

from flask import (Blueprint, current_app, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import connect, new_id, now

bp = Blueprint("auth", __name__)

SESSION_KEY = "user_id"
MIN_PASSWORD_LENGTH = 10
TOKEN_PREFIX = "sloth_"

# Endpoints reachable without being logged in.
PUBLIC_ENDPOINTS = {"auth.login", "auth.setup", "static"}


# --- storage -------------------------------------------------------------

def user_count():
    conn = connect()
    try:
        return conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    finally:
        conn.close()


def get_user(user_id):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1",
                            (user_id,)).fetchone()
    finally:
        conn.close()


def get_user_by_name(username):
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,)).fetchone()
    finally:
        conn.close()


def create_user(username, password):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    username = username.strip()
    if not username:
        raise ValueError("Username is required.")
    uid = new_id()
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO users (id, username, password_hash, created_at, is_active)"
            " VALUES (?,?,?,?,1)",
            (uid, username, generate_password_hash(password), now()))
        conn.commit()
    finally:
        conn.close()
    return uid


def set_password(user_id, password):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    conn = connect()
    try:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (generate_password_hash(password), user_id))
        conn.commit()
    finally:
        conn.close()


def issue_api_token(user_id):
    """Generates a token, stores only its hash, and returns it once."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    conn = connect()
    try:
        conn.execute("UPDATE users SET api_token_hash = ? WHERE id = ?",
                     (generate_password_hash(token), user_id))
        conn.commit()
    finally:
        conn.close()
    return token


def revoke_api_token(user_id):
    conn = connect()
    try:
        conn.execute("UPDATE users SET api_token_hash = NULL WHERE id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def _user_for_token(token):
    if not token or not token.startswith(TOKEN_PREFIX):
        return None
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM users WHERE api_token_hash IS NOT NULL AND is_active = 1"
        ).fetchall()
    finally:
        conn.close()
    for row in rows:
        if check_password_hash(row["api_token_hash"], token):
            return row
    return None


# --- brute-force throttling ---------------------------------------------

class _Throttle:
    """Slows down password guessing. In-memory, per client address."""

    LIMIT = 8
    WINDOW = 300      # failures older than this stop counting
    LOCKOUT = 300     # how long a tripped client waits

    def __init__(self):
        self._lock = threading.Lock()
        self._failures = {}

    def locked_for(self, key):
        with self._lock:
            entry = self._failures.get(key)
            if not entry:
                return 0
            stamps, until = entry
            remaining = until - time.monotonic()
            return int(remaining) if remaining > 0 else 0

    def record_failure(self, key):
        cutoff = time.monotonic() - self.WINDOW
        with self._lock:
            stamps, until = self._failures.get(key, ([], 0))
            stamps = [s for s in stamps if s > cutoff]
            stamps.append(time.monotonic())
            if len(stamps) >= self.LIMIT:
                until = time.monotonic() + self.LOCKOUT
                stamps = []
            self._failures[key] = (stamps, until)

    def clear(self, key):
        with self._lock:
            self._failures.pop(key, None)


throttle = _Throttle()


# --- request hooks -------------------------------------------------------

def current_user():
    return getattr(g, "user", None)


def _wants_json():
    return (request.is_json
            or request.headers.get("X-API-Token")
            or request.headers.get("Authorization", "").startswith("Bearer ")
            or request.accept_mimetypes.best == "application/json")


def load_user():
    """Resolves the caller from an API token or the session cookie."""
    g.user = None
    token = request.headers.get("X-API-Token")
    if not token:
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            token = header[7:].strip()
    if token:
        g.user = _user_for_token(token)
        g.via_token = g.user is not None
        if g.user is not None:
            return
    uid = session.get(SESSION_KEY)
    if uid:
        g.user = get_user(uid)
        if g.user is None:
            session.pop(SESSION_KEY, None)   # account deleted or disabled


def require_login():
    """Blocks anything that isn't public until the caller is authenticated."""
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if current_user() is not None:
        return None
    # A fresh install has no account yet — send the first visitor to setup
    # rather than to a login form nobody can pass.
    if user_count() == 0:
        if _wants_json():
            return jsonify({"error": "Setup required: create an account in the "
                                     "browser at /setup first."}), 401
        if request.endpoint != "auth.setup":
            return redirect(url_for("auth.setup"))
        return None
    if _wants_json():
        return jsonify({"error": "Authentication required."}), 401
    return redirect(url_for("auth.login", next=request.full_path))


def login_required(view):
    """For use outside the global hook, if a blueprint ever opts out."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper


# --- views ---------------------------------------------------------------

@bp.route("/setup", methods=["GET", "POST"])
def setup():
    # Only reachable while no account exists; otherwise it would be a way to
    # mint a second administrator without authenticating.
    if user_count() > 0:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        error = None
        if password != confirm:
            error = "Those passwords do not match."
        else:
            try:
                uid = create_user(username, password)
            except ValueError as exc:
                error = str(exc)
            else:
                session.clear()
                session[SESSION_KEY] = uid
                session.permanent = True
                flash("Account created — you are signed in.", "ok")
                return redirect(url_for("projects.index"))
        flash(error, "error")

    return render_template("setup.html", min_length=MIN_PASSWORD_LENGTH)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user() is not None:
        return redirect(url_for("projects.index"))
    if user_count() == 0:
        return redirect(url_for("auth.setup"))

    key = request.remote_addr or "unknown"
    if request.method == "POST":
        wait = throttle.locked_for(key)
        if wait:
            flash(f"Too many failed attempts. Try again in {wait} seconds.", "error")
            return render_template("login.html"), 429

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = get_user_by_name(username)
        # Hash even when the user does not exist, so the response time does not
        # reveal which usernames are real.
        stored = user["password_hash"] if user else _DUMMY_HASH
        if check_password_hash(stored, password) and user is not None:
            throttle.clear(key)
            session.clear()
            session[SESSION_KEY] = user["id"]
            session.permanent = True
            _touch_login(user["id"])
            nxt = request.args.get("next") or request.form.get("next")
            if nxt and nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            return redirect(url_for("projects.index"))

        throttle.record_failure(key)
        flash("Incorrect username or password.", "error")

    return render_template("login.html")


@bp.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    flash("Signed out.", "ok")
    return redirect(url_for("auth.login"))


@bp.route("/account", methods=["GET"])
def account():
    from . import tools
    import shutil
    user = current_user()
    return render_template("account.html", nav_section="account", user=user,
                           min_length=MIN_PASSWORD_LENGTH,
                           has_token=bool(user and user["api_token_hash"]),
                           shodan_configured=tools.shodan_key_configured(),
                           shodan_installed=bool(shutil.which("shodan")))


@bp.route("/account/shodan-key", methods=["POST"])
def shodan_key():
    from . import tools
    if request.form.get("remove"):
        tools.set_shodan_key("")
        flash("Shodan API key removed.", "ok")
    else:
        key = (request.form.get("api_key") or "").strip()
        if not key:
            flash("Paste a Shodan API key.", "error")
        else:
            tools.set_shodan_key(key)
            flash("Shodan API key saved.", "ok")
    return redirect(url_for("auth.account"))


@bp.route("/account/password", methods=["POST"])
def change_password():
    user = current_user()
    current = request.form.get("current_password") or ""
    new = request.form.get("new_password") or ""
    confirm = request.form.get("confirm") or ""

    if not check_password_hash(user["password_hash"], current):
        flash("Current password is incorrect.", "error")
    elif new != confirm:
        flash("Those passwords do not match.", "error")
    else:
        try:
            set_password(user["id"], new)
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("Password changed.", "ok")
    return redirect(url_for("auth.account"))


@bp.route("/account/token", methods=["POST"])
def rotate_token():
    user = current_user()
    if request.form.get("revoke"):
        revoke_api_token(user["id"])
        flash("API token revoked.", "ok")
        return redirect(url_for("auth.account"))
    token = issue_api_token(user["id"])
    # Shown once: only the hash is stored, so it cannot be displayed again.
    flash(f"New API token (copy it now, it will not be shown again): {token}", "ok")
    return redirect(url_for("auth.account"))


def _touch_login(user_id):
    conn = connect()
    try:
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now(), user_id))
        conn.commit()
    finally:
        conn.close()


# A real hash to compare against for unknown usernames, so a failed lookup costs
# the same time as a wrong password.
_DUMMY_HASH = generate_password_hash("unused-placeholder-value")
