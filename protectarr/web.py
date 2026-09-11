"""Flask WebUI: Servarr-style settings page + Forms login server."""

import io
import os
import time
import hmac
import zipfile
import base64
import secrets
import threading
from datetime import timedelta

from flask import (Flask, render_template, request, redirect, url_for,
                   jsonify, flash, session, Response, send_file, g)
from werkzeug.security import generate_password_hash, check_password_hash

from . import config as cfg_mod
from . import logs
from . import __version__
from .netauth import resolve_client_ip, is_local
from .qbit import QbitClient
from .arr import ArrClient, ARR_TYPES, build_clients
from .core import DOWNLOADING_STATES

# Endpoints reachable without a session (login form + static assets + health).
PUBLIC_ENDPOINTS = {"login", "static", "ping"}
# JSON endpoints - respond 401 rather than redirecting to the login page.
API_ENDPOINTS = {"test_qbit", "test_arr", "preview", "dashboard_data",
                 "api_index", "api_status", "api_stats", "api_watchlist",
                 "api_log", "api_preview", "api_command", "api_history",
                 "api_logfiles"}
BASIC_REALM = 'Basic realm="Protectarr", charset="UTF-8"'

# Settings sub-pages: (key, label, icon, description). qBittorrent + the *arr
# apps live on their own top-level "Applications" page, not under Settings.
SETTINGS_SECTIONS_FULL = [
    ("detection", "Monitored Extensions", "", "File extensions that flag a download for removal (e.g. .exe), and scan scope."),
    ("safety", "Safety", "", "Which torrents may be reaped, and air-date-aware requeue."),
    ("blocklist", "IP Blocklist", "", "Bulk peer IP filter applied to qBittorrent (BT_BlockLists)."),
    ("bannedips", "Banned IPs", "", "A small hand-curated list of banned IPs (API only)."),
    ("security", "Security", "", "Authentication for this WebUI."),
    ("logging", "Logging", "", "Log level, daily rotation and retention, and log downloads."),
]
SETTINGS_SECTIONS = [(k, l, i) for k, l, i, _ in SETTINGS_SECTIONS_FULL]
SETTINGS_KEYS = {k for k, *_ in SETTINGS_SECTIONS_FULL}


def _human_size(n):
    """Bytes -> the sizes people recognise from a torrent client."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return None
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return None


def _safe_next(nxt):
    """Only allow same-site relative paths as post-login redirect targets."""
    if nxt and nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt:
        return nxt
    return None


def create_app(service):
    app = Flask(__name__)
    app.secret_key = cfg_mod.ensure_secret_key()
    cfg_mod.ensure_api_key()  # auto-generate a web API key on first run
    app.permanent_session_lifetime = timedelta(days=30)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

    # login brute-force throttle (per client IP, in-memory)
    login_fails, login_lock = {}, threading.Lock()
    MAX_FAILS, FAIL_WINDOW = 10, 300

    def login_blocked(ip):
        now = time.time()
        with login_lock:
            recent = [t for t in login_fails.get(ip, []) if now - t < FAIL_WINDOW]
            login_fails[ip] = recent
            return len(recent) >= MAX_FAILS

    def record_login_fail(ip):
        with login_lock:
            login_fails.setdefault(ip, []).append(time.time())

    def clear_login_fails(ip):
        with login_lock:
            login_fails.pop(ip, None)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        return resp

    @app.context_processor
    def inject_csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf"]}

    def auth_cfg():
        return cfg_mod.load()["web"].get("auth", {})

    def valid_api_key(cfg):
        key = cfg["web"].get("api_key", "")
        given = request.headers.get("X-Api-Key") or request.args.get("apikey")
        return bool(key) and bool(given) and hmac.compare_digest(given, key)

    def csrf_ok():
        token = session.get("csrf")
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        return bool(token) and bool(sent) and hmac.compare_digest(token, sent)

    def check_password(auth, username, password):
        return (username == auth.get("username")
                and auth.get("password_hash")
                and check_password_hash(auth["password_hash"], password))

    def check_basic(auth):
        hdr = request.headers.get("Authorization", "")
        if not hdr.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(hdr[6:]).decode("utf-8")
            user, _, pw = raw.partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        if check_password(auth, user, pw):
            g.auth_user = user
            return True
        return False

    def request_is_local(auth):
        ip = resolve_client_ip(request.remote_addr,
                               request.headers.get("X-Forwarded-For"),
                               auth.get("trusted_proxies", []))
        return is_local(ip)

    @app.before_request
    def guard():
        cfg = cfg_mod.load()
        # CSRF: cookie-authenticated state changes must carry a valid token.
        # API-key callers are exempt (no cookies, not browser-driven).
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and not valid_api_key(cfg):
            if not csrf_ok():
                return Response("CSRF token missing or invalid", 400)
        if request.endpoint in PUBLIC_ENDPOINTS:
            return
        auth = cfg["web"].get("auth", {})
        method = auth.get("method", "none")
        if method == "none":
            return
        if valid_api_key(cfg):
            return
        # "Disabled for Local Addresses" - bypass auth for LAN/private clients.
        if auth.get("required") == "local_disabled" and request_is_local(auth):
            return
        if method == "basic":
            if check_basic(auth):
                return
            return Response("Authentication required", 401,
                            {"WWW-Authenticate": BASIC_REALM})
        # forms
        if session.get("authed"):
            return
        if request.endpoint in API_ENDPOINTS:
            return Response("Unauthorized", 401)
        return redirect(url_for("login", next=request.path))

    # ---- auth ----
    @app.route("/login", methods=["GET", "POST"])
    def login():
        auth = auth_cfg()
        if auth.get("method") != "forms":
            return redirect(url_for("applications"))
        nxt = _safe_next(request.values.get("next")) or url_for("applications")
        ip = request.remote_addr or "?"
        if request.method == "POST":
            if login_blocked(ip):
                return render_template("login.html",
                                       error="Too many attempts. Try again later.", next=nxt), 429
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            if check_password(auth, u, p):
                clear_login_fails(ip)
                session["authed"] = True
                session["user"] = u
                session.permanent = request.form.get("remember") == "on"
                return redirect(nxt)
            record_login_fail(ip)
            return render_template("login.html", error="Incorrect username or password.", next=nxt)
        return render_template("login.html", next=nxt)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---- pages ----
    def page(template, active, active_sub=None, **ctx):
        return render_template(
            template, active=active, active_sub=active_sub,
            cfg=cfg_mod.load(), state=service.state,
            arr_types=sorted(ARR_TYPES.keys()),
            settings_sections=SETTINGS_SECTIONS,
            settings_sections_full=SETTINGS_SECTIONS_FULL,
            version=__version__, config_path=cfg_mod.CONFIG_PATH,
            user=session.get("user"), basic_user=getattr(g, "auth_user", None),
            api_key_from_env=cfg_mod.api_key_is_from_env(),
            log_lines=logs.ring(), log_levels=logs.LEVELS,
            timezones=logs.available_timezones(),
            current_tz=time.strftime("%Z %z"),
            **ctx)

    @app.route("/")
    def applications():
        return page("applications.html", active="applications")

    @app.route("/dashboard")
    def dashboard():
        return page("dashboard.html", active="dashboard")

    @app.route("/system")
    def system():
        return page("system.html", active="system")

    @app.route("/watchlist")
    def watchlist():
        from . import harvest
        return page("watchlist.html", active="watchlist",
                    rows=harvest.watchlist())

    @app.route("/history")
    def history():
        from . import events
        # Default to Live so a burst of dry-run testing can't make the page look
        # like Protectarr stopped three hundred attacks.
        show = (request.args.get("show") or "live").lower()
        if show not in ("live", "dry", "all"):
            show = "live"
        dry = {"live": False, "dry": True, "all": None}[show]
        rows = []
        for e in events.read(limit=250, dry_run=dry):
            findings, decisive, severity, profile = events.normalize(e)
            rows.append({
                "ev": e,
                "why": events.describe(decisive),
                "also": [events.describe(f) for f in findings if f is not decisive],
                "severity": severity,
                "profile": profile,
                "requeue": events.describe_requeue(e.get("redownload")),
                "size": _human_size((e.get("torrent") or {}).get("size")),
            })
        return page("history.html", active="history", rows=rows, show=show)

    @app.route("/settings")
    def settings_index():
        return page("settings_index.html", active="settings")

    @app.route("/settings/<section>")
    def settings_page(section):
        if section not in SETTINGS_KEYS:
            return redirect(url_for("settings_index"))
        extra = {}
        if section == "logging":
            files = logs.list_files(cfg_mod.load())
            for f in files:
                f["size_h"] = _human_size(f["size"])
                f["modified_h"] = time.strftime("%Y-%m-%d %H:%M:%S",
                                                time.localtime(f["modified"]))
            extra = {"log_files": files,
                     "log_total_h": _human_size(sum(f["size"] for f in files))}
        return page(f"s_{section}.html", active="settings", active_sub=section, **extra)

    @app.route("/settings/<section>/save", methods=["POST"])
    def save_section(section):
        if section not in SETTINGS_KEYS:
            return redirect(url_for("settings_index"))
        cfg = cfg_mod.load()
        f = request.form

        if section == "detection":
            exts = []
            for raw in f.get("blocked_extensions", "").replace(",", "\n").splitlines():
                e = raw.strip().lower()
                if e:
                    exts.append(e if e.startswith(".") else "." + e)
            if exts:
                cfg["detection"]["blocked_extensions"] = exts
            cfg["detection"]["only_active"] = f.get("only_active") == "on"
            # Tier 2 - filename lure keywords
            cfg["detection"]["blocked_name_keywords"] = [
                k.strip().lower() for k in
                f.get("blocked_name_keywords", "").replace(",", "\n").splitlines()
                if k.strip()]
            # Tier 3 - indexer-scoped archive detection
            ad = cfg["detection"].setdefault("archive_detection", {})
            ad["enabled"] = f.get("archive_enabled") == "on"
            ad["indexers"] = [i.strip() for i in f.getlist("archive_indexers") if i.strip()]

        elif section == "safety":
            cfg["dry_run"] = f.get("dry_run") == "on"
            s = cfg["safety"]
            s["mode"] = f.get("safety_mode", "arr_tracked")
            s["allowed_categories"] = [c.strip() for c in
                f.get("allowed_categories", "").replace(",", "\n").splitlines() if c.strip()]
            s["allowed_tags"] = [c.strip() for c in
                f.get("allowed_tags", "").replace(",", "\n").splitlines() if c.strip()]
            s["requeue_after_airdate"] = f.get("requeue_after_airdate") == "on"
            s["airdate_grace_hours"] = max(0, int(f.get("airdate_grace_hours", 0) or 0))

        elif section == "blocklist":
            bl = cfg.setdefault("ip_blocklist", {})
            bl["enabled"] = f.get("bl_enabled") == "on"
            bl["url"] = f.get("bl_url", "").strip()
            bl["path"] = f.get("bl_path", "").strip()
            bl["update_interval_hours"] = max(1, int(f.get("bl_interval", 24) or 24))
            bl["apply_to_qbit"] = f.get("bl_apply") == "on"
            bl["block_trackers"] = f.get("bl_trackers") == "on"

        elif section == "bannedips":
            bip = cfg.setdefault("banned_ips", {})
            bip["enabled"] = f.get("bip_enabled") == "on"
            bip["ips"] = [x.strip() for x in
                f.get("bip_ips", "").replace(",", "\n").splitlines() if x.strip()]
            bip["merge_existing"] = f.get("bip_merge") == "on"

        elif section == "logging":
            lg = cfg.setdefault("logging", {})
            for key, field in (("level", "log_level"),
                               ("console_level", "log_console_level")):
                val = (f.get(field) or "").strip().lower()
                if val in logs.LEVELS:
                    lg[key] = val
            lg["file_enabled"] = f.get("log_file_enabled") == "on"
            lg["path"] = f.get("log_path", "").strip()
            lg["retention_days"] = max(0, int(f.get("log_retention", 14) or 0))
            tz = (f.get("timezone") or "").strip()
            if tz and tz not in logs.available_timezones():
                flash(f"Unknown timezone {tz!r}, leaving it unchanged.")
            else:
                cfg["timezone"] = tz

        elif section == "security":
            auth = cfg["web"].setdefault("auth", {})
            auth["method"] = f.get("auth_method", "none")
            auth["required"] = f.get("auth_required", "enabled")
            auth["username"] = f.get("auth_username", "").strip()
            if f.get("auth_password", ""):
                auth["password_hash"] = generate_password_hash(f["auth_password"])
            auth["trusted_proxies"] = [c.strip() for c in
                f.get("trusted_proxies", "").replace(",", "\n").splitlines() if c.strip()]

        cfg_mod.save(cfg)
        if section == "logging":
            logs.configure(cfg)   # new level/rotation takes effect immediately
        service.reload()
        # Optional "…and apply/update now" - runs against the just-saved config
        # so the action reflects the current form values (not stale ones).
        if section == "bannedips":
            service.apply_banned_ips(cfg)
        elif section == "blocklist" and f.get("do_update"):
            service.update_blocklist(cfg, force=True)
        flash("Settings saved.")
        return redirect(url_for("settings_page", section=section))

    # ---- applications (qBittorrent + the *arr apps live together) ----
    @app.route("/applications/qbit/save", methods=["POST"])
    def save_qbit():
        cfg = cfg_mod.load()
        f = request.form
        q = cfg["qbittorrent"]
        q["url"] = f.get("qbit_url", "").strip()
        q["api_key"] = f.get("qbit_api_key", "").strip()
        q["username"] = f.get("qbit_username", "").strip()
        if f.get("qbit_password", ""):
            q["password"] = f["qbit_password"]
        q["verify_ssl"] = f.get("qbit_verify_ssl") == "on"
        cfg["qbittorrent"]["web_url"] = f.get("qbit_web_url", "").strip()
        cfg_mod.save(cfg)
        service.reload()
        flash("qBittorrent settings saved.")
        return redirect(url_for("applications"))

    @app.route("/applications/app/save", methods=["POST"])
    def save_app():
        cfg = cfg_mod.load()
        f = request.form
        name = f.get("arr_name", "").strip()
        url = f.get("arr_url", "").strip()
        atype = f.get("arr_type", "").strip().lower()
        if not name or not url or atype not in ARR_TYPES:
            flash("Name, a valid type, and URL are required.")
            return redirect(url_for("applications"))
        entry = {"name": name, "type": atype, "url": url,
                 "api_key": f.get("arr_key", "").strip()}
        web_url = f.get("arr_web_url", "").strip()
        if web_url:
            entry["web_url"] = web_url
        arrs = cfg.get("arrs", [])
        idx = f.get("arr_index", "")
        if idx.isdigit() and int(idx) < len(arrs):
            arrs[int(idx)] = entry
        else:
            arrs.append(entry)
        cfg["arrs"] = arrs
        cfg_mod.save(cfg)
        service.reload()
        flash("Application saved.")
        return redirect(url_for("applications"))

    @app.route("/applications/app/delete", methods=["POST"])
    def delete_app():
        cfg = cfg_mod.load()
        arrs = cfg.get("arrs", [])
        idx = request.form.get("arr_index", "")
        if idx.isdigit() and int(idx) < len(arrs):
            removed = arrs.pop(int(idx))
            cfg["arrs"] = arrs
            cfg_mod.save(cfg)
            service.reload()
            flash(f"Removed {removed.get('name', 'application')}.")
        return redirect(url_for("applications"))

    # ---- dashboard live data (qBittorrent + arr/indexer inventory) ----
    @app.route("/api/dashboard", endpoint="dashboard_data")
    def dashboard_data():
        cfg = cfg_mod.load()
        data = {"active_torrents": None, "total_torrents": None,
                "indexers": [], "apps": [], "errors": []}
        try:
            qc = cfg["qbittorrent"]
            qb = QbitClient(qc["url"], qc.get("username", ""), qc.get("password", ""),
                            api_key=qc.get("api_key", ""), verify_ssl=qc.get("verify_ssl", True))
            qb.login()
            torrents = qb.torrents()
            data["total_torrents"] = len(torrents)
            data["active_torrents"] = sum(1 for t in torrents
                                          if t.get("state") in DOWNLOADING_STATES)
        except Exception as e:
            data["errors"].append(f"qBittorrent: {e}")

        seen = {}
        for client in build_clients(cfg):
            row = {"name": client.name, "type": client.type,
                   "ok": None, "detail": "", "indexers": 0, "library": None}
            try:
                ok, msg = client.test()
                row["ok"], row["detail"] = ok, msg
            except Exception as e:
                row["ok"], row["detail"] = False, str(e)
            try:
                row["library"] = client.library_stats()
            except Exception as e:
                data["errors"].append(f"{client.name} library: {e}")
            try:
                for ix in client.indexers():
                    row["indexers"] += 1
                    ent = seen.setdefault(ix["name"], {
                        "name": ix["name"], "protocol": ix.get("protocol", ""),
                        "enabled": ix.get("enabled", True), "apps": []})
                    if client.name not in ent["apps"]:
                        ent["apps"].append(client.name)
            except Exception as e:
                data["errors"].append(f"{client.name} indexers: {e}")
            data["apps"].append(row)
        data["indexers"] = sorted(seen.values(), key=lambda r: r["name"].lower())
        return jsonify(ok=True, data=data)

    # ---- test / preview / control ----
    @app.route("/test/qbit", methods=["POST"], endpoint="test_qbit")
    def test_qbit():
        d = request.json or {}
        stored = cfg_mod.load()["qbittorrent"]
        qb = QbitClient(d.get("url", ""), d.get("username", ""),
                        d.get("password", "") or stored["password"],
                        api_key=d.get("api_key", "") or stored.get("api_key", ""),
                        verify_ssl=d.get("verify_ssl", True))
        ok, msg = qb.test()
        return jsonify(ok=ok, message=msg)

    @app.route("/test/arr", methods=["POST"], endpoint="test_arr")
    def test_arr():
        d = request.json or {}
        try:
            client = ArrClient(d.get("name", "arr"), d.get("type", ""),
                               d.get("url", ""), d.get("api_key", ""))
        except ValueError as e:
            return jsonify(ok=False, message=str(e))
        ok, msg = client.test()
        return jsonify(ok=ok, message=msg)

    @app.route("/preview", endpoint="preview")
    def preview():
        try:
            return jsonify(ok=True, actions=service.preview())
        except Exception as e:
            return jsonify(ok=False, message=str(e))

    @app.route("/blocklist/update", methods=["POST"])
    def blocklist_update():
        service.update_blocklist(cfg_mod.load(), force=True)
        flash("IP blocklist update triggered.")
        return redirect(url_for("settings_page", section="blocklist"))

    @app.route("/settings/security/apikey/regenerate", methods=["POST"])
    def regenerate_api_key():
        new = cfg_mod.regenerate_api_key()
        if new is None:
            flash("The API key comes from PROTECTARR_WEB_API_KEY; change it there.")
        else:
            # Auth reads the key per request, so the old one is already dead.
            flash("New API key generated. The previous key no longer works.")
        return redirect(url_for("settings_page", section="security"))

    @app.route("/logs/download/<path:name>")
    def download_log(name):
        # resolve_file validates by membership in the real listing, so a
        # traversal attempt is simply not in the set.
        path = logs.resolve_file(cfg_mod.load(), name)
        if not path:
            return Response("No such log file", 404)
        return send_file(path, as_attachment=True, download_name=name)

    @app.route("/logs/download-all")
    def download_all_logs():
        cfg = cfg_mod.load()
        files = logs.list_files(cfg)
        if not files:
            return Response("No log files", 404)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for entry in files:
                path = logs.resolve_file(cfg, entry["name"])
                if path:
                    z.write(path, arcname=entry["name"])
        buf.seek(0)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return send_file(buf, mimetype="application/zip", as_attachment=True,
                         download_name=f"protectarr-logs-{stamp}.zip")

    @app.route("/bannedips/apply", methods=["POST"])
    def bannedips_apply():
        service.apply_banned_ips(cfg_mod.load())
        flash("Manually banned IPs applied to qBittorrent.")
        return redirect(url_for("settings_page", section="bannedips"))

    @app.route("/control/<action>", methods=["POST"])
    def control(action):
        if action == "start":
            service.start()
        elif action == "stop":
            service.stop()
        return redirect(url_for("applications"))

    # ---- public HTTP API (v1) - authenticate with the X-Api-Key header ----
    # (or ?apikey=). Same key shown in Settings > Security. Callers are exempt
    # from CSRF; forms-auth returns 401 JSON rather than redirecting.
    @app.route("/ping")
    def ping():
        return jsonify(status="ok", app="Protectarr", version=__version__)

    @app.route("/api/v1")
    def api_index():
        return jsonify(app="Protectarr", version=__version__, endpoints=[
            "GET  /api/v1/system/status", "GET  /api/v1/stats",
            "GET  /api/v1/watchlist", "GET  /api/v1/log?limit=N",
            "GET  /api/v1/history?limit=N&show=all|live|dry",
            "GET  /api/v1/logfiles",
            "GET  /api/v1/preview",
            "POST /api/v1/command {name: start|stop|scan|blocklistUpdate}",
        ])

    @app.route("/api/v1/system/status")
    def api_status():
        cfg = cfg_mod.load()
        st = service.state
        return jsonify(app="Protectarr", version=__version__,
                       running=st.get("running", False),
                       dryRun=bool(cfg.get("dry_run", True)),
                       lastScan=st.get("last_scan"), lastError=st.get("last_error"))

    @app.route("/api/v1/stats")
    def api_stats():
        st = service.state
        return jsonify(reaped=st.get("stats", {}),
                       blocklist=st.get("blocklist", {}),
                       banned=st.get("banned", {}))

    @app.route("/api/v1/watchlist")
    def api_watchlist():
        from . import harvest
        return jsonify(harvest.watchlist(min_fakes=request.args.get("min_fakes", type=int) or 1))

    @app.route("/api/v1/history")
    def api_history():
        from . import events
        n = min(max(request.args.get("limit", type=int) or 100, 1), 1000)
        dry = {"live": False, "dry": True}.get(
            (request.args.get("show") or "all").lower())
        return jsonify(events.read(limit=n, dry_run=dry))

    @app.route("/api/v1/logfiles")
    def api_logfiles():
        return jsonify(logs.list_files(cfg_mod.load()))

    @app.route("/api/v1/log")
    def api_log():
        n = request.args.get("limit", type=int) or 100
        return jsonify(logs.ring(n))

    @app.route("/api/v1/preview")
    def api_preview():
        try:
            return jsonify(ok=True, actions=service.preview())
        except Exception as e:
            return jsonify(ok=False, message=str(e)), 500

    @app.route("/api/v1/command", methods=["POST"])
    def api_command():
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or request.form.get("name") or "").strip().lower()
        if name == "start":
            service.start()
            return jsonify(ok=True, command="start", running=True)
        if name == "stop":
            service.stop()
            return jsonify(ok=True, command="stop", running=False)
        if name in ("scan", "scannow"):
            try:
                return jsonify(ok=True, command="scan", result=service.scan_now())
            except Exception as e:
                return jsonify(ok=False, command="scan", message=str(e)), 502
        if name == "blocklistupdate":
            service.update_blocklist(cfg_mod.load(), force=True)
            return jsonify(ok=True, command="blocklistUpdate")
        return jsonify(ok=False, message="unknown command; valid: "
                       "start, stop, scan, blocklistUpdate"), 400

    return app
