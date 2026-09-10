"""Configuration loading, defaults, env overrides, and saving (YAML)."""

import os
import copy
import secrets
import threading

import yaml

CONFIG_PATH = os.environ.get("PROTECTARR_CONFIG", "/config/config.yaml")

# Sensible defaults. The YAML file overrides these; env vars override the file
# for secrets (handy for Docker).
DEFAULTS = {
    "qbittorrent": {
        "url": "http://localhost:8080",
        # Optional browser-facing URL (if you reach qBittorrent at a different
        # address than the backend `url`). Used only for the "open" link.
        "web_url": "",
        # API key (qBittorrent >= 5.2.0). If set, it's used instead of
        # username/password.
        "api_key": "",
        "username": "admin",
        "password": "",
        "verify_ssl": True,
    },
    # Each arr: name, type (sonarr|radarr|lidarr|readarr|whisparr), url, api_key,
    # and an optional web_url (browser-facing address for the "open" link).
    "arrs": [],
    "detection": {
        "blocked_extensions": [
            ".exe", ".scr", ".bat", ".com", ".cmd", ".msi", ".pif",
            ".vbs", ".vbe", ".js", ".jse", ".jar", ".lnk", ".ps1",
            ".apk", ".dll", ".msc", ".hta",
        ],
        # Only inspect torrents still acquiring data (the point is to catch a
        # fake before it finishes). Skips finished seeds — huge speedup on big
        # libraries. Sonarr/Radarr's own "Fail Downloads" remains the backstop
        # for anything that happens to complete between polls.
        "only_active": True,
    },
    "safety": {
        # arr_tracked : reap only torrents a configured arr has in its queue
        # allowlist   : reap anything whose category/tag is allowlisted
        # both        : must be arr-tracked AND allowlisted
        "mode": "arr_tracked",
        "allowed_categories": [],
        "allowed_tags": [],
        # After reaping, requeue (search for a clean release) ONLY if the
        # episode/movie has already aired/released. If it hasn't, no legit
        # release can exist yet, so we hold and let the arr's normal RSS pick up
        # the real one when it drops. Set False to never requeue (blocklist only).
        "requeue_after_airdate": True,
        # Hours to wait past the air/release time before considering it "out"
        # (web releases often land a bit after the broadcast slot).
        "airdate_grace_hours": 0,
    },
    "poll_interval": 20,
    "dry_run": True,
    # Seeder-IP harvest: on each reap, enumerate the fake's swarm from
    # qBittorrent and log the peers to an observation ledger (harvest.json) for
    # pattern-spotting. Passive — collects data only, never bans on its own.
    "harvest": {
        "enabled": True,
    },
    # Optional peer IP blocklist (Naunter/BT_BlockLists) applied to qBittorrent's
    # IP filter. The file is written to `path`, which qBittorrent must be able to
    # read — in Docker that means a volume shared by both containers.
    "ip_blocklist": {
        "enabled": False,
        "url": "https://github.com/Naunter/BT_BlockLists/raw/master/bt_blocklists.gz",
        "path": "/blocklist/ipfilter.p2p",
        "update_interval_hours": 24,
        "apply_to_qbit": True,     # set qBittorrent ip_filter_enabled + ip_filter_path
        "block_trackers": False,   # also apply the filter to tracker connections
    },
    # A small, hand-curated list of individual IPs pushed to qBittorrent's
    # "manually banned IPs" via the API. No file/shared volume needed.
    "banned_ips": {
        "enabled": False,
        "ips": [],
        "merge_existing": True,    # union with qBittorrent's current banned list
    },
    "web": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 8090,
        # Optional API key for programmatic access (X-Api-Key header or ?apikey=).
        "api_key": "",
        # Session-cookie signing secret; auto-generated on first run.
        "secret_key": "",
        # Authentication, modelled on the arr apps (Settings > Security).
        "auth": {
            "method": "none",         # none | basic | forms
            # enabled | local_disabled (bypass auth for LAN/private addresses)
            "required": "enabled",
            "username": "",
            "password_hash": "",      # werkzeug hash; set via the UI
            # CIDRs of reverse proxies whose X-Forwarded-For may be trusted when
            # deciding whether a request is "local". Leave empty if not proxied.
            "trusted_proxies": [],
        },
    },
}

# Env overrides for secrets/paths. (env var -> path in config dict)
_ENV_OVERRIDES = {
    "PROTECTARR_QBIT_URL": ("qbittorrent", "url"),
    "PROTECTARR_QBIT_API_KEY": ("qbittorrent", "api_key"),
    "PROTECTARR_QBIT_USERNAME": ("qbittorrent", "username"),
    "PROTECTARR_QBIT_PASSWORD": ("qbittorrent", "password"),
    "PROTECTARR_WEB_API_KEY": ("web", "api_key"),
    "PROTECTARR_DRY_RUN": ("dry_run",),
}

_lock = threading.Lock()


def _deep_merge(base, override):
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _apply_env(cfg):
    for env, path in _ENV_OVERRIDES.items():
        if env not in os.environ:
            continue
        val = os.environ[env]
        if path[-1] == "dry_run":
            val = val.strip().lower() in ("1", "true", "yes", "on")
        node = cfg
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = val
    return cfg


def load():
    """Read config from disk merged over defaults, then apply env overrides."""
    with _lock:
        file_cfg = {}
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as fh:
                file_cfg = yaml.safe_load(fh) or {}
        cfg = _deep_merge(DEFAULTS, file_cfg)
        return _apply_env(cfg)


def _read_file():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as fh:
            return yaml.safe_load(fh) or {}
    return {}


def ensure_secret_key():
    """Return a stable session-signing key, generating + persisting one on first
    run. Operates on the raw file so env-injected secrets aren't written back."""
    with _lock:
        file_cfg = _read_file()
        key = (file_cfg.get("web") or {}).get("secret_key")
        if not key:
            key = secrets.token_hex(32)
            file_cfg.setdefault("web", {})["secret_key"] = key
            clean = _deep_merge(DEFAULTS, file_cfg)
            os.makedirs(os.path.dirname(CONFIG_PATH) or ".", exist_ok=True)
            tmp = CONFIG_PATH + ".tmp"
            with open(tmp, "w") as fh:
                yaml.safe_dump(clean, fh, sort_keys=False, default_flow_style=False)
            os.replace(tmp, CONFIG_PATH)
        return key


def save(cfg):
    """Persist config to disk (env overrides are NOT written back)."""
    with _lock:
        os.makedirs(os.path.dirname(CONFIG_PATH) or ".", exist_ok=True)
        # Only store keys we know about, in a stable order.
        clean = _deep_merge(DEFAULTS, cfg)
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w") as fh:
            yaml.safe_dump(clean, fh, sort_keys=False, default_flow_style=False)
        os.replace(tmp, CONFIG_PATH)
        return clean
