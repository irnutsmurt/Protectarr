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
            ".apk", ".dll", ".msc", ".hta", ".url", ".wsf", ".reg", ".cpl",
        ],
        # Tier 2 - flag by *filename*, not just extension: a lure file (readme /
        # url / nfo) whose name contains one of these substrings. Only checked
        # against text-like companion files, so a legit release simply titled
        # "Password" isn't a false positive.
        "blocked_name_keywords": [
            "password", "passw0rd", "how to download", "how to play",
        ],
        # Tier 3 - archive-with-no-media. RISKY (legit scene releases ship as
        # RARs), so it's OPT-IN and scoped to specific indexers: it only fires
        # for an *arr-tracked torrent whose indexer is in this list. Private
        # trackers (where RARs are legit) are safe by default.
        "archive_detection": {
            "enabled": False,
            "indexers": [],
            "archive_extensions": [
                ".rar", ".zip", ".7z", ".z01", ".zipx", ".tar",
                ".gz", ".bz2", ".arj", ".cab",
            ],
        },
        # Content probe: read the first piece of a media file and check it
        # really is that kind of file. Catches a payload wearing a genuine
        # `.mkv`/`.mp4` extension, which no amount of metadata inspection can
        # see. OFF by default: it costs a few MB per torrent, it needs to be
        # able to read qBittorrent's download directory, and it temporarily
        # changes per-file priorities (always restored - see probe/ledger.py).
        "probe": {
            "enabled": False,
            # qBittorrent's path -> the path this process can read it at.
            # [{from: /downloads, to: /downloads}]. Required unless both run in
            # the same filesystem namespace with identical paths.
            "path_mappings": [],
            # False = only ever read pieces the torrent already happens to have.
            # Costs nothing and changes nothing, but resolves fewer torrents.
            "steer": True,
            # Steering budget. Reading already-downloaded headers is free and is
            # not capped; these cap only the steered half.
            "max_torrents_per_scan": 1,
            "torrent_timeout_seconds": 120,
            "scan_budget_seconds": 120,
            # Don't spend budget on a torrent too slow to fetch the piece in
            # time: steering only influences the NEXT piece libtorrent picks.
            "min_speed_kib": 20,
            "min_seeds": 0,
            "header_bytes": 4096,
            # Don't re-steer the same torrent more often than this.
            "recheck_minutes": 15,
            "poll_seconds": 3,
            "stall_checks": 5,
            # Give up on a steer qBittorrent is ignoring. A torrent can be
            # downloading at full speed and still never request the piece we
            # asked for; measured, that stayed true for five minutes. There is
            # no reason to hold the boost for the whole budget once the piece
            # has plainly not been scheduled.
            "no_progress_seconds": 30,
        },
        # Only inspect torrents still acquiring data (the point is to catch a
        # fake before it finishes). Skips finished seeds - huge speedup on big
        # libraries. Sonarr/Radarr's own "Fail Downloads" remains the backstop
        # for anything that happens to complete between polls.
        "only_active": True,
        # How findings are judged. Detectors report what they saw; the profile
        # decides how serious that is here and what to do about it. `media`
        # blocks on everything, which is what Protectarr has always done - so
        # leaving this alone changes nothing. `software` treats an executable
        # as expected. Set per *arr (a `profile` key on the entry) or per
        # category (safety.category_profiles); this is the fallback.
        "profile": "media",
        # Override individual rules, or define your own profile:
        #   profiles:
        #     media:
        #       lure_filename: {severity: medium, decision: warn}
        "profiles": {},
    },
    "safety": {
        # arr_tracked : reap only torrents a configured arr has in its queue
        # allowlist   : reap anything whose category/tag is allowlisted
        # both        : must be arr-tracked AND allowlisted
        "mode": "arr_tracked",
        "allowed_categories": [],
        "allowed_tags": [],
        # qBittorrent category -> profile name, for torrents no *arr owns.
        "category_profiles": {},
        # After reaping, requeue (search for a clean release) ONLY if the
        # episode/movie has already aired/released. If it hasn't, no legit
        # release can exist yet, so we hold and let the arr's normal RSS pick up
        # the real one when it drops. Set False to never requeue (blocklist only).
        "requeue_after_airdate": True,
        # Hours to wait past the air/release time before considering it "out"
        # (web releases often land a bit after the broadcast slot).
        "airdate_grace_hours": 0,
        # How long a torrent must be CONTINUOUSLY and VERIFIABLY absent from
        # its owner's queue before Protectarr treats it as abandoned. Only
        # passes where that queue was actually read count, so an *arr that is
        # down does not age its own downloads into orphans.
        "orphan_dwell_minutes": 10,
        # How often to forget torrents qBittorrent no longer has. Needs the
        # full inventory, which measured 389 ms against a 1208-torrent library,
        # so it is cheap hourly and pointless more often.
        "ownership_prune_minutes": 60,
    },
    "poll_interval": 20,
    "dry_run": True,
    # IANA zone name (e.g. America/Los_Angeles). Blank uses the TZ environment
    # variable, which is what `TZ=` in docker-compose sets; with neither, a
    # container runs on UTC. Applies to every timestamp Protectarr writes.
    "timezone": "",
    # Logging. The file is rotated at midnight, gzipped, and kept for
    # retention_days before deletion. `level` applies to the file and the WebUI
    # log; `console_level` is what goes to stdout (what `docker logs` shows), so
    # the file can be verbose while the console stays readable.
    # Credentials are redacted from every sink, so a log is safe to attach to a
    # GitHub issue.
    "logging": {
        "level": "info",           # debug | info | warning | error
        "console_level": "info",
        "file_enabled": True,
        "path": "",                # blank = <config dir>/logs
        "retention_days": 14,
    },
    # Swarm observations: on each reap, enumerate the fake's swarm from
    # qBittorrent before removing it and record the peers as evidence
    # (evidence.db) for pattern-spotting. Passive - collects data only, never
    # bans on its own.
    #
    # The retention numbers are config-only on purpose. They came out of a
    # growth model measured against real swarm captures, and none of them is a
    # choice an operator can make well from a form without that curve in front
    # of them. Detail expires first and profiles outlive it, because an IP's
    # recurrence is the evidence worth keeping long after the per-peer detail
    # of any one encounter has stopped being interesting.
    "harvest": {
        "enabled": True,
        "detail_encounters": 2000,      # keep per-peer detail for the newest N
        "single_profile_days": 90,      # IPs seen in exactly one encounter
        "recurring_profile_days": 365,  # IPs seen in two or more
    },
    # Optional peer IP blocklist (Naunter/BT_BlockLists) applied to qBittorrent's
    # IP filter. The file is written to `path`, which qBittorrent must be able to
    # read - in Docker that means a volume shared by both containers.
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


def _env_value(name):
    """What this override actually supplies, or None when it supplies nothing.

    An empty or whitespace-only variable means "not provided", not "set to
    blank". `docker-compose.yml` ships

        - PROTECTARR_QBIT_PASSWORD=${QBIT_PASSWORD:-}

    and `${VAR:-}` *defines* the variable as empty rather than leaving it out,
    so an `name in os.environ` test made the stock compose file blank a
    password that had been set through the WebUI, on every single load, with
    the file on disk still holding the right value. Nothing can set one of
    these to a deliberate empty string that the UI could not set more
    directly, so there is no case being lost here.
    """
    val = os.environ.get(name)
    if val is None or not val.strip():
        return None
    return val


def _env_pairs():
    """(path, value) for every override currently supplying something."""
    out = []
    for env, path in _ENV_OVERRIDES.items():
        val = _env_value(env)
        if val is None:
            continue
        if path[-1] == "dry_run":
            val = val.strip().lower() in ("1", "true", "yes", "on")
        out.append((path, val))
    return out


def _dig(node, path):
    """Walk `path` through nested dicts. (containing dict, key) or (None, key)."""
    for key in path[:-1]:
        node = node.get(key) if isinstance(node, dict) else None
        if node is None:
            return None, path[-1]
    return (node if isinstance(node, dict) else None), path[-1]


def _deep_merge(base, override):
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _apply_env(cfg):
    for path, val in _env_pairs():
        node = cfg
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = val
    return cfg


def _strip_env(cfg, file_cfg):
    """Undo `_apply_env` for anything nobody edited, in place.

    `save()` is handed the dict `load()` produced, which has the environment
    already merged into it. Persisting that verbatim copies an env-provided
    secret onto disk because some unrelated page was saved, which is precisely
    what `save()` has always promised it does not do.

    A value is only taken back out when it still equals what the environment
    supplied, so an operator who deliberately changed the field still gets it
    written - shadowed by the variable until that variable goes away, which is
    the same outcome as before this function existed. Restoring what the file
    itself said (and deleting the key when it said nothing, so `_persist`'s
    merge supplies the default) is what keeps a save from being a quiet way to
    lose a stored credential.
    """
    for path, val in _env_pairs():
        node, key = _dig(cfg, path)
        if node is None or key not in node or node[key] != val:
            continue
        stored, _ = _dig(file_cfg, path)
        if stored is not None and key in stored:
            node[key] = stored[key]
        else:
            node.pop(key, None)
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


def _persist(file_cfg):
    """Write the raw file merged over defaults, atomically. Caller holds _lock."""
    clean = _deep_merge(DEFAULTS, file_cfg)
    os.makedirs(os.path.dirname(CONFIG_PATH) or ".", exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as fh:
        yaml.safe_dump(clean, fh, sort_keys=False, default_flow_style=False)
    os.replace(tmp, CONFIG_PATH)
    return clean


def ensure_secret_key():
    """Return a stable session-signing key, generating + persisting one on first
    run. Operates on the raw file so env-injected secrets aren't written back."""
    with _lock:
        file_cfg = _read_file()
        key = (file_cfg.get("web") or {}).get("secret_key")
        if not key:
            key = secrets.token_hex(32)
            file_cfg.setdefault("web", {})["secret_key"] = key
            _persist(file_cfg)
        return key


def ensure_api_key():
    """Return a stable web API key, generating + persisting one on first run so
    the HTTP API is usable out of the box (like the *arr apps). Skips generation
    when the key is supplied via the PROTECTARR_WEB_API_KEY env override."""
    env = _env_value("PROTECTARR_WEB_API_KEY")
    if env:
        return env
    with _lock:
        file_cfg = _read_file()
        key = (file_cfg.get("web") or {}).get("api_key")
        if not key:
            key = secrets.token_hex(32)
            file_cfg.setdefault("web", {})["api_key"] = key
            _persist(file_cfg)
        return key


def api_key_is_from_env():
    return _env_value("PROTECTARR_WEB_API_KEY") is not None


def regenerate_api_key():
    """Issue a new web API key, revoking the old one immediately.

    Auth reads the key from config on every request, so the change takes effect
    at once with no restart - and anything still presenting the old key starts
    getting 401. Returns the new key, or None if the key is pinned by the
    PROTECTARR_WEB_API_KEY env override, where rotating the file would silently
    do nothing.
    """
    if api_key_is_from_env():
        return None
    with _lock:
        file_cfg = _read_file()
        key = secrets.token_hex(32)
        file_cfg.setdefault("web", {})["api_key"] = key
        _persist(file_cfg)
        return key


def save(cfg):
    """Persist config to disk (env overrides are NOT written back).

    The copy matters: `_strip_env` edits what it is given, and the caller is
    holding the same dict it is about to keep using.
    """
    with _lock:
        # Only store keys we know about, in a stable order.
        return _persist(_strip_env(copy.deepcopy(cfg), _read_file()))
