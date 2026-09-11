"""Minimal qBittorrent Web API client.

Supports both auth methods:
  * API key (qBittorrent >= 5.2.0 / WebAPI >= 2.14.1) - stateless Bearer token,
    key looks like `qbt_...`. Preferred when set.
  * Username/password - cookie login via /api/v2/auth/login (older versions).

We read the torrent list and each torrent's *file list* - which comes from the
torrent metadata and is available before the content downloads - so an
executable can be spotted almost immediately.
"""

import requests


class QbitError(Exception):
    pass


class QbitClient:
    def __init__(self, url, username="", password="", api_key="",
                 verify_ssl=True, timeout=15):
        self.base = url.rstrip("/")
        self.username = username
        self.password = password
        self.api_key = (api_key or "").strip()
        self.timeout = timeout
        self._s = requests.Session()
        self._s.verify = verify_ssl
        if self.api_key:
            self._s.headers.update({"Authorization": f"Bearer {self.api_key}"})
        self._ready = bool(self.api_key)  # key auth needs no login step

    def login(self):
        """Cookie login (username/password). No-op when using an API key."""
        if self.api_key:
            self._ready = True
            return
        try:
            r = self._s.post(
                f"{self.base}/api/v2/auth/login",
                data={"username": self.username, "password": self.password},
                headers={"Referer": self.base},
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise QbitError(f"Connection error: {e}")
        if r.text.strip() != "Ok.":
            raise QbitError("Login failed (check username/password or Web UI host allowlist)")
        self._ready = True

    def _get(self, path, **params):
        if not self._ready:
            self.login()
        r = self._s.get(f"{self.base}/api/v2/{path}", params=params, timeout=self.timeout)
        if r.status_code in (401, 403):
            if self.api_key:
                # Bearer keys can't be refreshed by us - surface the failure.
                raise QbitError(f"Unauthorized (HTTP {r.status_code}) - check the qBittorrent API key")
            # Cookie expired - re-auth once and retry.
            self._ready = False
            self.login()
            r = self._s.get(f"{self.base}/api/v2/{path}", params=params, timeout=self.timeout)
        r.raise_for_status()
        return r

    def test(self):
        """Return (ok, message)."""
        try:
            if not self.api_key:
                self.login()
            r = self._get("app/version")
            return True, f"qBittorrent {r.text.strip()}"
        except (QbitError, requests.RequestException) as e:
            return False, str(e)

    def torrents(self, category=None):
        params = {}
        if category:
            params["category"] = category
        return self._get("torrents/info", **params).json()

    def files(self, torrent_hash):
        return self._get("torrents/files", hash=torrent_hash).json()

    def peers(self, torrent_hash):
        """Enumerate the current swarm for a torrent via the sync API. Returns a
        list of peer dicts. MUST be called before the torrent is removed - once
        it's gone from qBittorrent the swarm is no longer queryable."""
        data = self._get("sync/torrentPeers", hash=torrent_hash, rid=0).json()
        out = []
        for key, p in (data.get("peers") or {}).items():
            ip = p.get("ip") or key.rsplit(":", 1)[0]
            if not ip:
                continue
            out.append({
                "ip": ip,
                "port": p.get("port"),
                "client": (p.get("client") or "").strip(),
                "progress": p.get("progress", 0) or 0,
                "flags": (p.get("flags") or "").strip(),
                "country": (p.get("country") or p.get("country_code") or "").strip(),
                "connection": (p.get("connection") or "").strip(),
            })
        return out

    def categories(self):
        return list(self._get("torrents/categories").json().keys())

    def tags(self):
        return self._get("torrents/tags").json()

    def get_preferences(self):
        return self._get("app/preferences").json()

    def set_preferences(self, prefs):
        """Update qBittorrent preferences (dict). Setting ip_filter_path also
        makes qBittorrent (re)load the filter file."""
        import json as _json
        if not self._ready:
            self.login()
        r = self._s.post(f"{self.base}/api/v2/app/setPreferences",
                         data={"json": _json.dumps(prefs)}, timeout=self.timeout)
        r.raise_for_status()

    def delete(self, torrent_hash, delete_files=True):
        """Direct removal from qBittorrent (used only when no arr owns it)."""
        if not self._ready:
            self.login()
        r = self._s.post(
            f"{self.base}/api/v2/torrents/delete",
            data={"hashes": torrent_hash, "deleteFiles": str(bool(delete_files)).lower()},
            timeout=self.timeout,
        )
        r.raise_for_status()
